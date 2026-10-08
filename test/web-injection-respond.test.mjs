import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { runXdr } from '../scripts/xdr-run.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { respond, createWebInjectionDecider, XDR_RULE_ID } from '../xdr/web-injection/respond.mjs';
import { decide as starterDecide } from '../src/decider.mjs';

const repo = fileURLToPath(new URL('../', import.meta.url));
const started = Date.parse('2026-10-08T00:00:00Z');
const normal = fixtureRequests().normal;
const attackTarget = { classId: normal.classId, projectId: normal.projectId,
  subjectId: normal.subjectId, deviceId: 'bbbbbbbbbbbbbbbb' };
const normalTarget = { ...attackTarget, deviceId: normal.deviceId };
const attack = { ...normal, ...attackTarget };
const decision = (alertId, action, confidence) => ({ alertId, action, confidence, reason: '시험 패턴' });
// 운영 정책 대신 사용하지 않는 가상 판정기와 시험용 허용 코드입니다.
const baseDecide = async request => ({
  schema: 'aleph.decision.v1', requestId: request.requestId,
  decision: request.deviceRegistered ? 'allow' : 'deny',
  reasonCode: request.deviceRegistered ? 'approved' : 'device_not_registered',
  ruleIds: ['device_registered'],
});
const wrap = (root, options = {}) => createWebInjectionDecider({
  root, baseDecide, baseRuleIds: ['device_registered'],
  reasonCode: 'xdr_fixture_deny', allowedReasonCodes: ['xdr_fixture_deny'],
  now: () => started, ...options,
});
const storePath = root => join(root, 'xdr', 'web-injection', 'deny-rules.json');
const rulesAt = async root => JSON.parse(await readFile(storePath(root), 'utf8')).rules;
async function temporary(t) {
  const root = await mkdtemp(join(repo, 'test', '.tmp-xdr-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('차단 후보만 만료·근거 규칙으로 만들며 기존 규칙과 정상 허용을 보존', async t => {
  const root = await temporary(t);
  await mkdir(join(root, 'xdr'));
  const existing = '기존 규칙 보존용 시험 자료';
  await writeFile(join(root, 'xdr', 'deny-rules.json'), existing);
  const targets = new Map([['wi-01', attackTarget], ['wi-09', normalTarget], ['wi-18', normalTarget]]);
  assert.deepEqual(await respond({ root, now: () => started,
    decisions: [decision('wi-01', 'block', 0.95), decision('wi-09', 'alert', 0.6),
      decision('wi-18', 'record', 0.1), decision('wi-unmapped', 'block', 0.95)],
    resolveVerifiedTarget: async ({ alertId }) => targets.get(alertId),
  }), { added: 1, skipped: 1 });
  const rules = await rulesAt(root);
  assert.equal(rules.length, 1);
  assert.equal(rules[0].alertId, 'wi-01');
  assert.equal(rules[0].ruleId, XDR_RULE_ID);
  assert.equal(rules[0].expiresAt, new Date(started + 600_000).toISOString());
  const decider = wrap(root);
  assert.equal((await decider.decide(attack)).decision, 'deny');
  assert.deepEqual(await decider.decide(normal), await baseDecide(normal));
  for (const field of ['classId', 'projectId', 'subjectId', 'deviceId']) {
    const other = { ...attack, [field]: field === 'deviceId' ? 'cccccccccccccccc' : 'other_fixture' };
    assert.deepEqual(await decider.decide(other), await baseDecide(other));
  }
  const denied = { ...attack, deviceRegistered: false };
  assert.deepEqual(await decider.decide(denied), await baseDecide(denied));
  assert.equal(await readFile(join(root, 'xdr', 'deny-rules.json'), 'utf8'), existing);
  const log = await readFile(join(root, 'xdr', 'alerts.log'), 'utf8');
  const lines = log.trim().split('\n').map(JSON.parse);
  assert.equal(lines.length, 3);
  assert.equal(lines[2].outcome, 'unmapped_candidate');
  assert.equal(log.includes(normal.subjectId), false);
  assert.equal(log.includes(attack.deviceId), false);
  assert.equal(log.includes('시험 패턴'), false);
});

test('정상 근거는 동일 대상의 신규 삽입과 기존 웹 주입 차단을 해제', async t => {
  const root = await temporary(t);
  const options = { root, now: () => started, resolveVerifiedTarget: async () => attackTarget };
  const batch = [decision('wi-01', 'block', 0.95), decision('wi-18', 'record', 0.1)];
  assert.deepEqual(await respond({ ...options, decisions: batch }), { added: 0, skipped: 1 });
  assert.equal((await wrap(root).decide(attack)).decision, 'allow');
  await respond({ ...options, decisions: [batch[0]] });
  assert.equal((await wrap(root).decide(attack)).decision, 'deny');
  await respond({ ...options, decisions: batch });
  assert.equal((await wrap(root).decide(attack)).decision, 'allow');
});

test('중복 경보는 만료를 연장하지 않으며 만료 뒤에는 기존 허용 유지', async t => {
  const root = await temporary(t);
  const options = { root, resolveVerifiedTarget: async () => attackTarget,
    decisions: [decision('wi-01', 'block', 0.95)] };
  await respond({ ...options, now: () => started });
  await respond({ ...options, now: () => started + 60_000 });
  assert.equal((await rulesAt(root)).length, 1);
  assert.equal(Date.parse((await rulesAt(root))[0].expiresAt), started + 600_000);
  assert.equal((await wrap(root, { now: () => started + 599_999 }).decide(attack)).decision, 'deny');
  assert.equal((await wrap(root, { now: () => started + 600_000 }).decide(attack)).decision, 'allow');
  assert.equal((await wrap(root, { now: () => started - 1 }).decide(attack)).decision, 'allow');
  await respond({ ...options, now: () => started + 600_000, decisions: [] });
  assert.equal((await rulesAt(root)).length, 0);
});

test('낮은 확신도·조회 실패·잘못된 경보는 규칙을 만들지 않고 원문은 숨김', async t => {
  const root = await temporary(t);
  assert.deepEqual(await respond({ root, now: () => started,
    decisions: [decision('wi-01', 'block', 0.6), decision('wi-02', 'block', 0.95),
      decision('wi-03\nprivate', 'block', 0.95)],
    resolveVerifiedTarget: async ({ alertId }) => {
      if (alertId === 'wi-02') throw new Error('synthetic-private-marker');
      return attackTarget;
    },
  }), { added: 0, skipped: 2 });
  assert.equal((await wrap(root).decide(attack)).decision, 'allow');
  assert.equal((await readFile(join(root, 'xdr', 'alerts.log'), 'utf8')).includes('private'), false);
  assert.throws(() => wrap(root, { allowedReasonCodes: [] }), /운영 등록부/);
  const decider = wrap(root, { baseDecide: starterDecide, baseRuleIds: ['starter.deny'] });
  assert.deepEqual(await decider.decide(normal), await starterDecide(normal));
});

test('실행기로 시험 경보를 두 번 흘리면 명확한 공격만 거부하고 정상·알림은 통과', async t => {
  const root = await temporary(t);
  await mkdir(join(root, 'xdr', 'fixtures'), { recursive: true });
  await mkdir(join(root, 'xdr', 'web-injection'));
  await cp(join(repo, 'xdr', 'fixtures', 'web-injection.json'), join(root, 'xdr', 'fixtures', 'web-injection.json'));
  for (const name of ['decide.mjs', 'patterns.mjs', 'respond.mjs']) {
    await cp(join(repo, 'xdr', 'web-injection', name), join(root, 'xdr', 'web-injection', name));
  }
  // 가상 매핑은 시험 안에서만 만들며 실제 경보의 IP·사용자에서 ID를 추측하지 않습니다.
  const targets = new Map(Array.from({ length: 26 }, (_, i) => [
    `wi-${String(i + 1).padStart(2, '0')}`,
    { ...normalTarget, deviceId: (i + 1).toString(16).padStart(16, '0') },
  ]));
  const options = { root, moduleKey: 'web-injection', resolveVerifiedTarget: async ({ alertId }) => targets.get(alertId) };
  const first = await runXdr(options);
  const before = await rulesAt(root);
  const second = await runXdr(options);
  assert.deepEqual(first.counts, { block: 8, alert: 9, record: 9 });
  assert.deepEqual(second, first);
  assert.deepEqual(await rulesAt(root), before);
  const decider = wrap(root, { now: () => Date.now() });
  for (const [alertId, target] of targets) {
    assert.equal((await decider.decide({ ...normal, ...target })).decision,
      Number(alertId.slice(3)) <= 8 ? 'deny' : 'allow', alertId);
  }
  const lines = (await readFile(join(root, 'xdr', 'alerts.log'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(lines.length, 34);
  assert.equal(lines.filter(line => line.action === 'alert' && line.outcome === 'notification').length, 18);
  for (const alertId of ['wi-10', 'wi-11', 'wi-12', 'wi-13', 'wi-14']) {
    assert.equal(before.some(rule => rule.alertId === alertId), false);
    assert.equal(lines.filter(line => line.alertId === alertId && line.outcome === 'notification').length, 2);
  }
  assert.equal(lines.filter(line => line.outcome === 'deny_rule_added').length, 8);
  assert.equal(lines.filter(line => line.outcome === 'existing_rule').length, 8);
});
