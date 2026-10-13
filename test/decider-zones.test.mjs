import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const id = '00000000-0000-4000-8000-000000000001';
const request = overrides => ({ ...fixtureRequests().normal, ...overrides });

test('exact note UUID routes allow read and update, with existing device and step-up checks', async () => {
  for (const prefix of ['', '/api']) {
    for (const method of ['GET', 'PUT']) {
      const input = request({ method, route: `${method} ${prefix}/notes/:id`, path: `${prefix}/notes/${id}` });
      const result = await decide(input);
      assert.equal(result.decision, 'allow');
      assert.ok(result.ruleIds.includes(method === 'GET' ? 'notes_read' : 'notes_update'));
      assert.ok(result.ruleIds.every(rule => RULE_IDS.includes(rule)));
      assert.deepEqual(Object.keys(result).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
      assert.equal((await decide({ ...input, deviceRegistered: false })).reasonCode, 'device_not_registered');
      const { suspicious } = fixtureRequests();
      assert.equal((await decide({ ...suspicious, method, route: input.route, path: input.path })).decision, 'step_up');
      assert.equal((await decide({ ...suspicious, method, route: input.route, path: input.path,
        stepUp: { verified: true, authAgeSeconds: 0 } })).decision, 'allow');
    }
  }
});

test('unknown paths, route-method mismatches and query function switches are denied', async () => {
  for (const path of ['/api/notes/export', '/api/notes/demo', '/api/notes/%65xport',
    `/api/notes/${id}/export`, `/api/notes/${id}/`, `/api/notes/${id}?action=edit`,
    '/api/notes/../instructor-notices', '/api/notes//export', '/api/notes', '/other']) {
    assert.equal((await decide(request({ path, route: 'GET /api/notes/:id' }))).decision, 'deny', path);
  }
  for (const changes of [
    { method: 'PUT' }, { service: 'other' }, { subjectId: '' }, { subjectId: ' ' },
    { deviceId: undefined }, { deviceId: 'forged' },
    { queryLength: 12 }, { queryLength: undefined }, { querySha256: 'forged' },
  ]) assert.equal((await decide(request(changes))).decision, 'deny');
  for (const method of ['POST', 'DELETE', 'PATCH']) {
    assert.equal((await decide(request({ method, route: `${method} /notes/:id` }))).decision, 'deny');
  }
  assert.equal((await decide(request({ path: '/api/notes', route: 'GET /api/notes' }))).decision, 'allow');
});

test('instructor notice updates stay denied without an engine-verified instructor grant', async () => {
  for (const prefix of ['', '/api']) {
    const input = request({ method: 'PUT', path: `${prefix}/instructor-notices/${id}`,
      route: `PUT ${prefix}/instructor-notices/:id`, role: 'instructor',
      identity: { role: 'instructor' }, headers: { 'x-role': 'instructor' } });
    const result = await decide(input);
    assert.equal(result.decision, 'deny');
    assert.deepEqual(result.ruleIds, ['instructor_notice_update']);
    assert.equal((await decide({ ...input, deviceRegistered: false })).reasonCode, 'device_not_registered');
  }
});
