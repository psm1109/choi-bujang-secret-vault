import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detect } from '../src/detect.mjs';
import { checkDetection } from '../scripts/detect-test.mjs';

const start = Date.UTC(2026, 9, 1);
const reads = (count, { interval = 2_000, subject = 'learner_fixture',
  deviceId = 'aaaaaaaaaaaaaaaa', network = 'unusual', offset = 0 } = {}) =>
  Array.from({ length: count }, (_, index) => ({
    at: new Date(start + offset + index * interval).toISOString(), method: 'GET',
    identity: { sub: subject }, deviceId, signals: { source: 'judge_fixture', network },
  }));
const observe = { action: 'observe' };
const proposal = { action: 'propose_revocation', reasonCode: 'burst_read',
  subject: 'learner_fixture', deviceId: 'aaaaaaaaaaaaaaaa' };

test('compound practice cases detect only the combined pattern', async () => {
  for (const result of await checkDetection(detect)) assert.equal(result.passed, true, result.name);
});

test('sliding windows handle unordered events, shifted windows and exact time boundaries', () => {
  const events = reads(121, { interval: 5_000, offset: 420_000 });
  const snapshot = structuredClone(events);
  assert.deepEqual(detect([...events].reverse()), proposal);
  assert.deepEqual(events, snapshot);
  events[120].at = new Date(start + 420_000 + 600_001).toISOString();
  assert.deepEqual(detect(events), observe);
  assert.deepEqual(detect(reads(120)), observe);
});

test('users, devices and usual-network events never pool into an unusual burst', () => {
  assert.deepEqual(detect([...reads(100), ...reads(100, { subject: 'other_fixture' })]), observe);
  assert.deepEqual(detect([...reads(100), ...reads(100, { deviceId: 'bbbbbbbbbbbbbbbb' })]), observe);
  assert.deepEqual(detect([...reads(100), ...reads(100, { network: 'usual' })]), observe);
  assert.deepEqual(detect([...reads(100), ...reads(100).map(({ deviceId, ...event }) => event)]), observe);
  assert.deepEqual(detect([...reads(121), ...reads(200, { deviceId: 'bbbbbbbbbbbbbbbb', network: 'usual' })]), proposal);
  assert.deepEqual(detect(reads(200, { deviceId: 'bbbbbbbbbbbbbbbb', network: 'usual' })), observe);
});

test('missing signals, invalid times and non-GET requests supply no burst evidence', () => {
  for (const signals of [undefined, {}, { source: 'none', network: 'unusual' },
    { source: 'judge_fixture', network: 'unknown' }]) {
    assert.deepEqual(detect(reads(200).map(event => ({ ...event, signals }))), observe);
  }
  for (const at of [undefined, null, 'invalid_fixture', '2026-02-30T00:00:00.000Z']) {
    assert.deepEqual(detect(reads(200).map(event => ({ ...event, at }))), observe);
  }
  assert.deepEqual(detect(reads(200).map(event => ({ ...event, method: 'POST' }))), observe);
});

test('compound detection never reads private fields or region and retains no history', () => {
  const events = reads(121);
  const unreadable = { get() { throw new Error('unexpected_private_field_access'); }, enumerable: true };
  for (const event of events) {
    for (const field of ['body', 'content', 'token', 'name', 'headers']) Object.defineProperty(event, field, unreadable);
    Object.defineProperty(event.identity, 'name', unreadable);
    Object.defineProperty(event.signals, 'region', unreadable);
  }
  assert.deepEqual(detect(events), proposal);
  assert.deepEqual(detect([]), observe);
  assert.deepEqual(detect(reads(1)), observe);
});

test('proposals identify just one supplied device and never fall back to a user-wide target', () => {
  const missingDevice = reads(200).map(({ deviceId, ...event }) => event);
  assert.deepEqual(detect(missingDevice), observe);
  const events = [...missingDevice, ...reads(200, { network: 'usual', deviceId: 'cccccccccccccccc' }),
    ...reads(121, { deviceId: 'bbbbbbbbbbbbbbbb' }), ...reads(121)];
  const snapshot = structuredClone(events);
  const result = detect(events);
  assert.deepEqual(result, { ...proposal, deviceId: 'bbbbbbbbbbbbbbbb' });
  assert.deepEqual(Object.keys(result).sort(), ['action', 'deviceId', 'reasonCode', 'subject']);
  assert.deepEqual(events, snapshot);
});
