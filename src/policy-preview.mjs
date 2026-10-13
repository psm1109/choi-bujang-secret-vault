import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFile, writeFile, rename, rm, lstat, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

export const POLICY_FILES = Object.freeze(['src/decider.mjs', 'src/detect.mjs']);
const MAX_BYTES = 256 * 1024;
const hash = value => createHash('sha256').update(value).digest('hex');
const fail = () => { throw new Error('정책 미리보기 중단: 사본·신뢰 공개키·서명·침해 전 검증 정보를 확인하세요.'); };
function timestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u.test(value)) fail();
  const result = Date.parse(value);
  if (!Number.isFinite(result) || new Date(result).toISOString() !== value) fail();
  return result;
}

// 본문은 출력하지 않고 변경된 줄 범위만 표시합니다. 공통 앞·뒤 구간은 제외합니다.
export function changedRange(current, backup) {
  if (current === backup) return null;
  const left = current.split('\n');
  const right = backup.split('\n');
  let first = 0;
  while (first < left.length && first < right.length && left[first] === right[first]) first++;
  let endLeft = left.length;
  let endRight = right.length;
  while (endLeft > first && endRight > first && left[endLeft - 1] === right[endRight - 1]) {
    endLeft--; endRight--;
  }
  return {
    current: { start: first + 1, lines: endLeft - first },
    backup: { start: first + 1, lines: endRight - first },
  };
}

export async function previewPolicy({ backupPath, signaturePath, publicKeyPath, before, trialRoot }) {
  try {
    const boundary = timestamp(before);
    if (!backupPath || !signaturePath || !publicKeyPath || !trialRoot) fail();
    const bytes = await readFile(backupPath);
    const signature = await readFile(signaturePath);
    const keyBytes = await readFile(publicKeyPath);
    if (bytes.length > MAX_BYTES || signature.length !== 64 || keyBytes.length > 16 * 1024) fail();
    const key = createPublicKey(keyBytes);
    if (key.asymmetricKeyType !== 'ed25519' || !verify(null, bytes, key, signature)) fail();
    const backup = JSON.parse(bytes.toString('utf8'));
    if (backup.schema !== 'aleph.policy-backup.v1'
        || typeof backup.version !== 'string' || !/^[a-zA-Z0-9._-]{1,80}$/u.test(backup.version)
        || timestamp(backup.createdAt) > timestamp(backup.verifiedAt)
        || timestamp(backup.verifiedAt) >= boundary
        || boundary > Date.now()
        || !backup.files || typeof backup.files !== 'object' || Array.isArray(backup.files)
        || Object.keys(backup.files).length !== POLICY_FILES.length
        || Object.keys(backup.files).some(name => !POLICY_FILES.includes(name))) fail();
    const changes = [];
    const currentHashes = {};
    for (const path of POLICY_FILES) {
      const entry = backup.files[path];
      if (!entry || typeof entry.content !== 'string'
          || Buffer.byteLength(entry.content) > MAX_BYTES
          || !/^[a-f0-9]{64}$/u.test(entry.sha256) || hash(entry.content) !== entry.sha256) fail();
      const currentBytes = await readFile(resolve(trialRoot, path));
      if (currentBytes.length > MAX_BYTES) fail();
      const current = currentBytes.toString('utf8');
      if (!Buffer.from(current).equals(currentBytes)) fail();
      currentHashes[path] = hash(currentBytes);
      const range = changedRange(current, entry.content);
      if (range) changes.push({ path, currentSha256: hash(currentBytes), backupSha256: entry.sha256, range });
    }
    const report = {
      mode: 'preview_only', version: backup.version,
      createdAt: backup.createdAt, verifiedAt: backup.verifiedAt,
      before, backupSha256: hash(bytes),
      trustedPublicKeySha256: hash(key.export({ type: 'spki', format: 'der' })),
      comparedFiles: [...POLICY_FILES], currentHashes, changes,
    };
    return { ...report, confirmation: hash(JSON.stringify(report)) };
  } catch {
    fail();
  }
}

// 복원은 명시적으로 표시한 별도 로컬 시험 사본에서만 수행합니다.
export async function restoreTrialPolicy(options, confirmation) {
  const root = await realpath(options.trialRoot);
  const workspace = await realpath(fileURLToPath(new URL('..', import.meta.url)));
  if (root.toLowerCase() === workspace.toLowerCase()) throw new Error('현재 자료실에는 복원할 수 없습니다. 별도 시험 사본을 사용하세요.');
  const marker = JSON.parse(await readFile(resolve(root, '.aleph-policy-trial.json'), 'utf8'));
  if (marker.schema !== 'aleph.policy-trial.v1' || marker.environment !== 'local-test') fail();
  const src = resolve(root, 'src');
  if ((await lstat(src)).isSymbolicLink()) fail();
  for (const path of POLICY_FILES) {
    const stat = await lstat(resolve(root, path));
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail();
  }
  const report = await previewPolicy({ ...options, trialRoot: root });
  if (confirmation !== report.confirmation) throw new Error('확인한 버전 또는 시험 정책이 달라졌습니다. 미리보기를 다시 확인하세요.');
  const bytes = await readFile(options.backupPath);
  if (hash(bytes) !== report.backupSha256) fail();
  const backup = JSON.parse(bytes.toString('utf8'));
  const originals = new Map();
  const staged = new Map();
  const written = [];
  try {
    for (const { path } of report.changes) {
      const target = resolve(root, path);
      const original = await readFile(target);
      if (hash(original) !== report.currentHashes[path]) fail();
      originals.set(path, original);
      const temporary = `${target}.restore-${randomUUID()}.tmp`;
      staged.set(path, temporary);
      await writeFile(temporary, backup.files[path].content, { flag: 'wx', mode: 0o600 });
    }
    // 변경하지 않는 대상도 미리보기 이후 달라졌으면 중단합니다.
    for (const path of POLICY_FILES) {
      if (hash(await readFile(resolve(root, path))) !== report.currentHashes[path]) fail();
    }
    for (const [path, temporary] of staged) {
      await rename(temporary, resolve(root, path));
      written.push(path);
    }
    return { ...report, mode: 'trial_restored', restoredFiles: written, verification: 'pending_local_request_tests' };
  } catch (error) {
    for (const path of written.reverse()) await writeFile(resolve(root, path), originals.get(path));
    throw error;
  } finally {
    for (const temporary of staged.values()) await rm(temporary, { force: true });
  }
}
