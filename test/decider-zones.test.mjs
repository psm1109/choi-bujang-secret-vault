import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const id = '00000000-0000-4000-8000-000000000001';
const request = overrides => ({ ...fixtureRequests().normal, ...overrides });

test('previous normal demo read survives UUID tightening without allowing functional paths', async () => {
  const input = request({ path: '/notes/demo', route: 'GET /notes/:id' });
  assert.equal((await decide(input)).decision, 'allow');
  assert.equal((await decide({ ...input, deviceRegistered: false })).decision, 'deny');
  const { suspicious } = fixtureRequests();
  assert.equal((await decide({ ...suspicious, path: input.path, route: input.route })).decision, 'step_up');
  for (const changes of [{ method: 'PUT', route: 'PUT /notes/:id' },
    { path: '/notes/export' }, { path: '/notes/demo/export' }, { path: '/notes/demo/' },
    { path: '/notes/%64emo' }, { queryLength: 12 },
    { path: '/api/notes/demo', route: 'GET /api/notes/:id' }]) {
    assert.equal((await decide({ ...input, ...changes })).decision, 'deny');
  }
});

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
});

test('whole-note collections and all notice or instructor-material writes are denied', async () => {
  for (const prefix of ['', '/api']) {
    const collection = request({ path: `${prefix}/notes`, route: `GET ${prefix}/notes` });
    assert.equal((await decide(collection)).decision, 'deny');
    assert.equal((await decide({ ...collection, queryLength: 12 })).decision, 'deny');
    for (const zone of ['instructor-notices', 'notices', 'announcements', 'instructor-materials']) {
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        for (const [path, route] of [[`${prefix}/${zone}`, `${method} ${prefix}/${zone}`],
          [`${prefix}/${zone}/${id}`, `${method} ${prefix}/${zone}/:id`]]) {
          assert.equal((await decide(request({ method, path, route }))).decision, 'deny', `${method} ${path}`);
        }
      }
    }
  }
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
