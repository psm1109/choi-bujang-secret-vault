import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { runXdr } from '../scripts/xdr-run.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { applyXdrDecisions, createXdrDecider, XDR_RULE_ID } from '../xdr/ztna-bridge.mjs';
import { decide as starterDecide } from '../src/decider.mjs';

const repo = fileURLToPath(new URL('../', import.meta.url));
const started = Date.parse('2026-10-08T00:00:00Z');
const normal = fixtureRequests().normal;
const attackTarget = { classId: normal.classId, projectId: normal.projectId,
  subjectId: normal.subjectId, deviceId: 'bbbbbbbbbbbbbbbb' };
const normalTarget = { ...attackTarget, deviceId: normal.deviceId };
const attack = { ...normal, ...attackTarget };
const decision = (alertId, action, confidence) => ({ alertId, action, confidence, reason: '시험 패턴' });
const baseDecide = async request => ({
  schema: 'aleph.decision.v1', requestId: request.requestId,
  decision: request.deviceRegistered ? 'allow' : 'deny',
  reasonCode: request.deviceRegistered ? 'approved' : 'device_not_registered',
  ruleIds: ['device_registered'],
});
const wrap = (root, options = {}) => createXdrDecider({
  root, baseDecide, baseRuleIds: ['device_registered'],
  reasonCode: 'xdr_fixture_deny', allowedReasonCodes: ['xdr_fixture_deny'],
  now: () => started, ...options,
});

async function temporary(t) {
  const root = await mkdtemp(join(repo, 'test', '.tmp-xdr-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('검증된 차단 후보만 규칙으로 만들고 정상·알림 대상은 기존 허용 유지', async t => {
  const root = await temporary(t);
  const targets = new Map([['bf-01', attackTarget], ['bf-11', normalTarget], ['bf-20', normalTarget]]);
  const result = await applyXdrDecisions({
    root, moduleKey: 'brute-force', now: () => started,
    decisions: [decision('bf-01', 'block', 0.95), decision('bf-11', 'alert', 0.6),
      decision('bf-20', 'record', 0.1), decision('bf-unmapped', 'block', 0.95)],
    resolveVerifiedTarget: async ({ alertId }) => targets.get(alertId),
  });
  assert.deepEqual(result, { added: 1, skipped: 1 });
  const { rules } = JSON.parse(await readFile(join(root, 'xdr', 'deny-rules.json'), 'utf8'));
  assert.equal(rules.length, 1);
  assert.equal(rules[0].alertId, 'bf-01');
  assert.equal(rules[0].expiresAt, new Date(started + 600_000).toISOString());
  const decider = wrap(root);
  assert.deepEqual(await decider.decide(attack), {
    schema: 'aleph.decision.v1', requestId: attack.requestId,
    decision: 'deny', reasonCode: 'xdr_fixture_deny', ruleIds: [XDR_RULE_ID],
  });
  assert.deepEqual(await decider.decide(normal), await baseDecide(normal));
  for (const field of ['classId', 'projectId', 'subjectId', 'deviceId']) {
    const unrelated = { ...attack, [field]: field === 'deviceId' ? 'cccccccccccccccc' : 'other_fixture' };
    assert.deepEqual(await decider.decide(unrelated), await baseDecide(unrelated));
  }
  const existingDenied = { ...attack, deviceRegistered: false };
  assert.deepEqual(await decider.decide(existingDenied), await baseDecide(existingDenied));
  const log = await readFile(join(root, 'xdr', 'alerts.log'), 'utf8');
  const lines = log.trim().split('\n').map(JSON.parse);
  assert.equal(lines.length, 3);
  assert.equal(lines[2].outcome, 'unmapped_candidate');
  assert.equal(log.includes(normal.subjectId), false);
  assert.equal(log.includes(attack.deviceId), false);
});

test('정상 근거가 있는 동일 주체·기기는 규칙 삽입과 기존 XDR 차단에서 제외', async t => {
  const root = await temporary(t);
  const options = { root, moduleKey: 'brute-force', now: () => started,
    resolveVerifiedTarget: async () => attackTarget };
  const batch = [decision('bf-01', 'block', 0.95), decision('bf-20', 'record', 0.1)];
  assert.deepEqual(await applyXdrDecisions({ ...options, decisions: batch }), { added: 0, skipped: 1 });
  assert.equal((await wrap(root).decide(attack)).decision, 'allow');
  await applyXdrDecisions({ ...options, decisions: [batch[0]] });
  assert.equal((await wrap(root).decide(attack)).decision, 'deny');
  await applyXdrDecisions({ ...options, decisions: batch });
  assert.equal((await wrap(root).decide(attack)).decision, 'allow');
});

test('만료 경계와 반복 입력: TTL 연장 없이 로그는 계속 추가', async t => {
  const root = await temporary(t);
  const options = { root, moduleKey: 'brute-force', resolveVerifiedTarget: async () => attackTarget,
    decisions: [decision('bf-01', 'block', 0.95)] };
  await applyXdrDecisions({ ...options, now: () => started });
  await applyXdrDecisions({ ...options, now: () => started + 60_000 });
  const { rules } = JSON.parse(await readFile(join(root, 'xdr', 'deny-rules.json'), 'utf8'));
  assert.equal(rules.length, 1);
  assert.equal(Date.parse(rules[0].expiresAt), started + 600_000);
  assert.equal((await wrap(root, { now: () => started + 599_999 }).decide(attack)).decision, 'deny');
  assert.equal((await wrap(root, { now: () => started + 600_000 }).decide(attack)).decision, 'allow');
  assert.equal((await wrap(root, { now: () => started - 1 }).decide(attack)).decision, 'allow');
  const lines = (await readFile(join(root, 'xdr', 'alerts.log'), 'utf8')).trim().split('\n');
  assert.equal(lines.length, 2);
});

test('낮은 확신도·조회 실패·잘못된 ID·다른 모듈은 차단 규칙을 만들지 않음', async t => {
  const root = await temporary(t);
  const options = { root, moduleKey: 'brute-force', now: () => started,
    decisions: [decision('bf-01', 'block', 0.6), decision('bf-02', 'block', 0.95),
      decision('bf-03\nsecret', 'block', 0.95)],
    resolveVerifiedTarget: async ({ alertId }) => {
      if (alertId === 'bf-02') throw new Error('synthetic-private-marker');
      return attackTarget;
    } };
  assert.deepEqual(await applyXdrDecisions(options), { added: 0, skipped: 2 });
  assert.deepEqual(await applyXdrDecisions({ ...options, moduleKey: 'web-injection' }), { added: 0, skipped: 0 });
  assert.equal((await wrap(root).decide(attack)).decision, 'allow');
  const log = await readFile(join(root, 'xdr', 'alerts.log'), 'utf8');
  assert.equal(log.includes('synthetic-private-marker'), false);
  assert.equal(log.includes('secret'), false);
});

test('운영 허용 코드 없이는 연결하지 않고 시작 틀의 deny를 그대로 보존', async t => {
  const root = await temporary(t);
  assert.throws(() => wrap(root, { allowedReasonCodes: [] }), /운영 등록부/);
  assert.throws(() => wrap(root, { reasonCode: undefined }), /운영 등록부/);
  const decider = wrap(root, { baseDecide: starterDecide, baseRuleIds: ['starter.deny'] });
  assert.deepEqual(await decider.decide(normal), await starterDecide(normal));
});

test('시험 경보를 실행기로 재전송하면 명확한 공격만 거부하고 정상 요청 허용', async t => {
  const root = await temporary(t);
  await mkdir(join(root, 'xdr', 'fixtures'), { recursive: true });
  await mkdir(join(root, 'xdr', 'brute-force'), { recursive: true });
  await cp(join(repo, 'xdr', 'fixtures', 'brute-force.json'), join(root, 'xdr', 'fixtures', 'brute-force.json'));
  for (const name of ['decide.mjs', 'patterns.json']) {
    await cp(join(repo, 'xdr', 'brute-force', name), join(root, 'xdr', 'brute-force', name));
  }
  const previousFetch = globalThis.fetch;
  const previousUrl = process.env.JEV_API_URL;
  const previousKey = process.env.JEV_API_KEY;
  t.after(() => {
    globalThis.fetch = previousFetch;
    for (const [name, value] of [['JEV_API_URL', previousUrl], ['JEV_API_KEY', previousKey]]) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  });
  process.env.JEV_API_URL = 'https://jev.invalid/confidence';
  process.env.JEV_API_KEY = 'test-only-placeholder';
  globalThis.fetch = async () => Response.json({ confidence: 0.65 });
  const targets = new Map(Array.from({ length: 28 }, (_, i) => [
    `bf-${String(i + 1).padStart(2, '0')}`,
    { ...normalTarget, deviceId: (i + 1).toString(16).padStart(16, '0') },
  ]));
  const options = { root, moduleKey: 'brute-force', resolveVerifiedTarget: async ({ alertId }) => targets.get(alertId) };
  const first = await runXdr(options);
  const second = await runXdr(options);
  assert.deepEqual(first.counts, { block: 10, alert: 9, record: 9 });
  assert.deepEqual(second.counts, first.counts);
  const rules = JSON.parse(await readFile(join(root, 'xdr', 'deny-rules.json'), 'utf8')).rules;
  assert.equal(rules.length, 10);
  const decider = wrap(root, { now: () => Date.now() });
  for (const [alertId, target] of targets) {
    const request = { ...normal, ...target };
    assert.equal((await decider.decide(request)).decision, Number(alertId.slice(3)) <= 10 ? 'deny' : 'allow');
  }
  const lines = (await readFile(join(root, 'xdr', 'alerts.log'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(lines.length, 38);
  assert.equal(lines.filter(line => line.outcome === 'deny_rule_added').length, 10);
  assert.equal(lines.filter(line => line.outcome === 'existing_rule').length, 10);
});
