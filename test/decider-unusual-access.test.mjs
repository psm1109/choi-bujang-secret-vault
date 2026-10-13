import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

test('compound fixture requests additional confirmation with a reason and preserves response contract', async () => {
  const { normal, suspicious } = fixtureRequests();
  assert.equal((await decide(normal)).decision, 'allow');
  const result = await decide(suspicious);
  assert.deepEqual(result, {
    schema: 'aleph.decision.v1', requestId: suspicious.requestId,
    decision: 'step_up', reasonCode: 'step_up_required',
    ruleIds: ['device_registered', 'unusual_access'],
  });
  assert.ok(result.ruleIds.every(id => RULE_IDS.includes(id)));
  // 지역을 바꿔도 동일한 복합 조건이면 추가 확인입니다.
  assert.equal((await decide({ ...suspicious,
    signals: { ...suspicious.signals, region: 'local' } })).decision, 'step_up');
});

test('engine fixture region labels do not make normal and compound verdicts identical', async () => {
  const { normal, suspicious } = fixtureRequests();
  const ordinary = await decide({ ...normal,
    signals: { ...normal.signals, region: 'region_a' } });
  const unusual = await decide({ ...suspicious,
    signals: { ...suspicious.signals, region: 'region_b' } });
  assert.equal(ordinary.decision, 'allow');
  assert.equal(unusual.decision, 'step_up');
  assert.equal(unusual.reasonCode, 'step_up_required');
  assert.equal((await decide({ ...normal,
    signals: { ...normal.signals, region: 'region_b' } })).decision, 'allow');
  for (const region of [undefined, null, '', [], {}]) {
    assert.equal((await decide({ ...normal,
      signals: { ...normal.signals, region } })).decision, 'deny');
  }
});

test('each incomplete combination and region alone remain allowed', async () => {
  const { normal, suspicious } = fixtureRequests();
  const requests = [
    { ...normal, signals: { ...normal.signals, region: 'foreign' } },
    { ...suspicious, signals: { ...suspicious.signals, hour: 6 } },
    { ...suspicious, signals: { ...suspicious.signals, hour: null } },
    { ...suspicious, signals: { ...suspicious.signals, network: 'usual' } },
    { ...suspicious, signals: { ...suspicious.signals, network: 'unknown' } },
    { ...suspicious, recentEvents: [] },
    { ...suspicious, recentEvents: [{ kind: 'risk_signal', ageSeconds: 61, count: 20 }] },
    { ...suspicious, recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 19 }] },
    { ...suspicious, recentEvents: [{ kind: 'other_event', ageSeconds: 60, count: 20 }] },
    { ...suspicious, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 3 },
      headers: { 'x-signals-source': 'judge_fixture', 'x-network': 'unusual' } },
  ];
  for (const request of requests) {
    const result = await decide(request);
    assert.equal(result.decision, 'allow');
    assert.equal(result.reasonCode, 'approved');
  }
  for (const hour of [0, 5]) {
    assert.equal((await decide({ ...suspicious,
      signals: { ...suspicious.signals, hour } })).decision, 'step_up');
  }
});

test('device and input checks precede additional confirmation and stepUp alone does not bypass it', async () => {
  const { suspicious } = fixtureRequests();
  const unregistered = await decide({ ...suspicious, deviceRegistered: false });
  assert.equal(unregistered.decision, 'deny');
  assert.equal(unregistered.reasonCode, 'device_not_registered');
  assert.equal((await decide({ ...suspicious, recentEvents: undefined })).decision, 'deny');
  assert.equal((await decide({ ...suspicious, method: 'POST' })).decision, 'deny');
  assert.equal((await decide({ ...suspicious,
    stepUp: { verified: true, authAgeSeconds: 60 } })).decision, 'step_up');
});
