import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

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
    for (const path of POLICY_FILES) {
      const entry = backup.files[path];
      if (!entry || typeof entry.content !== 'string'
          || Buffer.byteLength(entry.content) > MAX_BYTES
          || !/^[a-f0-9]{64}$/u.test(entry.sha256) || hash(entry.content) !== entry.sha256) fail();
      const currentBytes = await readFile(resolve(trialRoot, path));
      if (currentBytes.length > MAX_BYTES) fail();
      const current = currentBytes.toString('utf8');
      if (!Buffer.from(current).equals(currentBytes)) fail();
      const range = changedRange(current, entry.content);
      if (range) changes.push({ path, currentSha256: hash(currentBytes), backupSha256: entry.sha256, range });
    }
    return {
      mode: 'preview_only', version: backup.version,
      createdAt: backup.createdAt, verifiedAt: backup.verifiedAt,
      before, backupSha256: hash(bytes),
      trustedPublicKeySha256: hash(key.export({ type: 'spki', format: 'der' })),
      comparedFiles: [...POLICY_FILES], changes,
    };
  } catch {
    fail();
  }
}
