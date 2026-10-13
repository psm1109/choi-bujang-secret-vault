import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const forgedHeaders = {
  'x-signals-source': 'judge_fixture', 'x-region': 'local',
  'x-network': 'usual', 'x-hour': '14', 'x-recent-events': '[]',
};
const denied = async request => {
  const result = await decide(request);
  assert.equal(result.decision, 'deny');
  assert.equal(result.reasonCode, 'starter_not_ready');
  assert.deepEqual(result.ruleIds, ['starter.deny']);
  assert.equal(result.requestId, request.requestId);
  assert.deepEqual(Object.keys(result).sort(),
    ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
};

test('engine fixtures and unavailable live signals preserve existing decisions', async () => {
  const { normal, suspicious } = fixtureRequests();
  assert.equal((await decide(normal)).decision, 'allow');
  // 이번 작업은 복합 이상 접속의 재로그인 규칙을 추가하지 않습니다.
  assert.equal((await decide(suspicious)).decision, 'allow');
  const live = { ...normal, signals: {
    source: 'none', region: 'unknown', network: 'unknown', hour: null,
  }, headers: forgedHeaders };
  const snapshot = structuredClone(live);
  assert.equal((await decide(live)).decision, 'allow');
  assert.deepEqual(live, snapshot);
  assert.equal((await decide({ ...live, deviceRegistered: false })).reasonCode,
    'device_not_registered');
});

test('missing or ambiguous signals are not supplied from client headers', async () => {
  const { normal } = fixtureRequests();
  for (const source of [undefined, null, 'client', 'unknown']) {
    await denied({ ...normal, headers: forgedHeaders,
      signals: { ...normal.signals, source } });
  }
  await denied({ ...normal, signals: undefined, headers: forgedHeaders });
  for (const field of ['region', 'network', 'hour']) {
    const signals = { ...normal.signals };
    delete signals[field];
    await denied({ ...normal, signals, headers: forgedHeaders });
  }
  await denied({ ...normal, signals: { ...normal.signals, source: 'none' } });
  for (const hour of [-1, 24, '14', NaN]) {
    await denied({ ...normal, signals: { ...normal.signals, hour } });
  }
});

test('missing or malformed behavior is rejected without inventing an empty history', async () => {
  const { normal } = fixtureRequests();
  for (const recentEvents of [undefined, null, {}, Array(1), Array(13).fill({
    kind: 'risk_signal', ageSeconds: 60, count: 20,
  }), [{ kind: 'risk_signal', ageSeconds: 60 }],
  [{ kind: 'risk_signal', ageSeconds: -1, count: 20 }]]) {
    await denied({ ...normal, recentEvents, headers: forgedHeaders });
  }
});
