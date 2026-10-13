import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detect, readDetectionEvents } from '../src/detect.mjs';

test('normal and suspicious fixtures expose only supplied pseudonyms and classifications', () => {
  const events = ['allow', 'step_up', 'deny'].map(decision => ({
    identity: { sub: 'learner_fixture' }, deviceId: 'a'.repeat(16),
    method: 'GET', decision,
  }));
  const snapshot = structuredClone(events);
  assert.deepEqual(readDetectionEvents(events), events.map(event => ({
    subject: 'learner_fixture', method: 'GET', deviceId: 'a'.repeat(16),
    decision: event.decision,
  })));
  assert.deepEqual(detect(events), { action: 'observe' });
  assert.deepEqual(events, snapshot);
});

test('private and unrelated fields are never read or copied', () => {
  const unreadable = { get() { throw new Error('unexpected_private_field_access'); }, enumerable: true };
  const identity = { sub: 'learner_fixture' };
  Object.defineProperty(identity, 'name', unreadable);
  const event = { identity, method: 'GET' };
  for (const field of ['body', 'content', 'memo', 'token', 'access_token', 'name', 'at']) {
    Object.defineProperty(event, field, unreadable);
  }
  assert.deepEqual(readDetectionEvents([event]), [{ subject: 'learner_fixture', method: 'GET' }]);
  assert.deepEqual(detect([event]), { action: 'observe' });
});

test('existing practice events remain valid without inventing device or decision values', () => {
  const events = Array.from({ length: 121 }, () => ({
    at: '2026-10-01T00:00:00.000Z', method: 'GET', identity: { sub: 'learner_fixture' },
  }));
  assert.deepEqual(readDetectionEvents(events)[0], { subject: 'learner_fixture', method: 'GET' });
  assert.deepEqual(detect(events), { action: 'observe' });
  assert.deepEqual(readDetectionEvents([]), []);
});

test('malformed inputs use fixed errors without echoing supplied values', () => {
  const valid = { identity: { sub: 'learner_fixture' }, method: 'GET' };
  assert.throws(() => readDetectionEvents({}), { message: 'invalid_detection_events' });
  for (const event of [null, [], undefined, {},
    { ...valid, identity: { sub: '' } }, { ...valid, method: 'invalid_fixture' },
    { ...valid, deviceId: 'invalid_fixture' }, { ...valid, decision: 'invalid_fixture' }]) {
    assert.throws(() => detect([event]), { message: 'invalid_detection_event' });
  }
  assert.throws(() => detect(Array(1)), { message: 'invalid_detection_event' });
});
