import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { previewPolicy, restoreTrialPolicy, changedRange, POLICY_FILES } from '../src/policy-preview.mjs';
import { pathToFileURL } from 'node:url';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'policy-preview-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'src'));
  await writeFile(join(root, '.aleph-policy-trial.json'), JSON.stringify({ schema: 'aleph.policy-trial.v1', environment: 'local-test' }));
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const backup = {
    schema: 'aleph.policy-backup.v1', version: 'safe-v9',
    createdAt: '2026-01-01T00:00:00.000Z', verifiedAt: '2026-01-02T00:00:00.000Z', files: {},
  };
  for (const path of POLICY_FILES) {
    const content = 'export const policy = "safe";\n';
    backup.files[path] = { content, sha256: createHash('sha256').update(content).digest('hex') };
    await writeFile(join(root, path), 'export const policy = "trial";\n');
  }
  const options = {
    trialRoot: root, backupPath: join(root, 'backup.json'), signaturePath: join(root, 'backup.sig'),
    publicKeyPath: join(root, 'public.pem'), before: '2026-01-03T00:00:00.000Z',
  };
  await writeFile(options.publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }));
  async function save() {
    const bytes = Buffer.from(JSON.stringify(backup));
    await writeFile(options.backupPath, bytes);
    await writeFile(options.signaturePath, sign(null, bytes, privateKey));
  }
  await save();
  return { options, backup, save };
}

test('검증된 사본의 버전·변경 범위를 표시하고 모든 입력 파일을 보존한다', async t => {
  const { options } = await fixture(t);
  const paths = [options.backupPath, options.signaturePath, options.publicKeyPath,
    ...POLICY_FILES.map(path => join(options.trialRoot, path))];
  const before = await Promise.all(paths.map(path => readFile(path)));
  const result = await previewPolicy(options);
  assert.equal(result.mode, 'preview_only');
  assert.equal(result.version, 'safe-v9');
  assert.equal(result.changes.length, 2);
  assert.deepEqual(result.changes[0].range, { current: { start: 1, lines: 1 }, backup: { start: 1, lines: 1 } });
  assert.deepEqual(await Promise.all(paths.map(path => readFile(path))), before);
  assert.ok(!JSON.stringify(result).includes('export const'));
});

test('동일 정책은 변경 없음으로 표시한다', async t => {
  const { options, backup } = await fixture(t);
  for (const path of POLICY_FILES) await writeFile(join(options.trialRoot, path), backup.files[path].content);
  assert.deepEqual((await previewPolicy(options)).changes, []);
});

for (const scenario of ['missing', 'tampered', 'wrong-key', 'hash', 'late', 'scope', 'missing-trial']) {
  test(`검증 실패 시 중단: ${scenario}`, async t => {
    const { options, backup, save } = await fixture(t);
    if (scenario === 'missing') options.backupPath += '.missing';
    if (scenario === 'tampered') await writeFile(options.backupPath, '{}');
    if (scenario === 'wrong-key') {
      const { publicKey } = generateKeyPairSync('ed25519');
      await writeFile(options.publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }));
    }
    if (scenario === 'hash') { backup.files[POLICY_FILES[1]].sha256 = '0'.repeat(64); await save(); }
    if (scenario === 'late') { backup.verifiedAt = options.before; await save(); }
    if (scenario === 'scope') { backup.files['api/auth.js'] = backup.files[POLICY_FILES[0]]; await save(); }
    if (scenario === 'missing-trial') await rm(join(options.trialRoot, POLICY_FILES[1]));
    await assert.rejects(previewPolicy(options), /정책 미리보기 중단/u);
  });
}

test('삽입·삭제 및 줄바꿈 변경 범위를 보존한다', () => {
  assert.deepEqual(changedRange('a\nb', 'a\nx\nb'), { current: { start: 2, lines: 0 }, backup: { start: 2, lines: 1 } });
  assert.deepEqual(changedRange('a\nx\nb', 'a\nb'), { current: { start: 2, lines: 1 }, backup: { start: 2, lines: 0 } });
  assert.notEqual(changedRange('a\n', 'a\r\n'), null);
});

test('확인한 두 정책만 복원하고 다른 서비스·감사 파일을 보존한다', async t => {
  const { options, backup, save } = await fixture(t);
  for (const path of POLICY_FILES) {
    const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
    backup.files[path] = { content, sha256: createHash('sha256').update(content).digest('hex') };
  }
  await save();
  await writeFile(join(options.trialRoot, 'other-service.mjs'), 'unchanged-service');
  await writeFile(join(options.trialRoot, 'audit.log'), 'unchanged-audit');
  const report = await previewPolicy(options);
  const result = await restoreTrialPolicy(options, report.confirmation);
  assert.equal(result.version, report.version);
  assert.deepEqual(result.restoredFiles, POLICY_FILES);
  assert.equal(await readFile(join(options.trialRoot, 'other-service.mjs'), 'utf8'), 'unchanged-service');
  assert.equal(await readFile(join(options.trialRoot, 'audit.log'), 'utf8'), 'unchanged-audit');
  const { decide } = await import(pathToFileURL(join(options.trialRoot, 'src/decider.mjs')));
  const normal = { ...fixtureRequests().normal, path: '/api/notes/00000000-0000-4000-8000-000000000001', route: 'GET /api/notes/:id' };
  assert.equal((await decide(normal)).decision, 'allow');
  assert.equal((await decide({ ...normal, deviceRegistered: false })).decision, 'deny');
  assert.deepEqual((await previewPolicy(options)).changes, []);
});

for (const scenario of ['no-confirmation', 'changed-trial', 'changed-version', 'no-marker']) {
  test(`복원 중단 후 원본 유지: ${scenario}`, async t => {
    const { options, backup, save } = await fixture(t);
    const report = await previewPolicy(options);
    let confirmation = report.confirmation;
    if (scenario === 'no-confirmation') confirmation = undefined;
    if (scenario === 'changed-trial') await writeFile(join(options.trialRoot, POLICY_FILES[0]), 'changed-after-preview');
    if (scenario === 'changed-version') { backup.version = 'different-v9'; await save(); }
    if (scenario === 'no-marker') await rm(join(options.trialRoot, '.aleph-policy-trial.json'));
    const before = await Promise.all(POLICY_FILES.map(path => readFile(join(options.trialRoot, path))));
    await assert.rejects(restoreTrialPolicy(options, confirmation));
    assert.deepEqual(await Promise.all(POLICY_FILES.map(path => readFile(join(options.trialRoot, path)))), before);
  });
}

