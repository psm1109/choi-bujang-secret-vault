import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';
import { createDeviceAccess } from '../public/device-access.js';
import handler from '../api/device-approval.js';

const session = { user: { id: 'fixture-user' }, access_token: 'fixture-in-memory',
  expires_at: Math.floor(Date.now() / 1000) + 3600 };
const statusResponse = (state, registered = state === 'registered') =>
  new Response(JSON.stringify({ schema: 'aleph.device-access.v1', state, registered }));

test('request acceptance alone grants nothing; only separate server status confirms registration', async () => {
  const states = [];
  let method;
  const access = createDeviceAccess({ onChange: state => states.push(state), schedule: () => 0,
    fetchStatus: async (url, options) => {
      assert.equal(url, '/api/device-approval');
      assert.equal(options.cache, 'no-store');
      assert.equal(options.redirect, 'error');
      method = options.method;
      return statusResponse('registered');
    } });
  assert.equal(await access.check(session, 'POST'), false);
  assert.equal(method, 'POST');
  assert.equal(access.registered, false);
  assert.equal(await access.check(session), true);
  assert.equal(method, 'GET');
  assert.equal(access.registered, true);
  access.invalidate();
  assert.equal(access.registered, false);
});

test('unregistered, pending, denied, missing contract and malformed responses stay closed', async () => {
  for (const response of [statusResponse('unregistered'), statusResponse('pending'), statusResponse('denied'),
    statusResponse('registered', false), statusResponse('unregistered', true),
    new Response('{}'), new Response('not-json'), new Response('{}', { status: 503 }),
    new Response('{}', { status: 401 })]) {
    const access = createDeviceAccess({ onChange() {}, fetchStatus: async () => response });
    assert.equal(await access.check(session), false);
    assert.equal(access.registered, false);
  }
  let calls = 0;
  const access = createDeviceAccess({ onChange() {}, fetchStatus: async () => { calls++; }, isOnline: () => false });
  assert.equal(await access.check(session), false);
  assert.equal(calls, 0);
});

test('late confirmation cannot reopen after logout, offline, expiry or a newer denied check', async () => {
  let resolve;
  let expired;
  const access = createDeviceAccess({ onChange() {}, schedule: callback => { expired = callback; return 0; },
    fetchStatus: () => new Promise(done => { resolve = done; }) });
  const late = access.check(session);
  access.invalidate('login_required');
  resolve(statusResponse('registered'));
  assert.equal(await late, false);
  const valid = access.check(session);
  resolve(statusResponse('registered'));
  assert.equal(await valid, true);
  expired();
  assert.equal(access.registered, false);
  const older = access.check(session);
  const olderResolve = resolve;
  const newer = access.check(session);
  resolve(statusResponse('denied'));
  assert.equal(await newer, false);
  olderResolve(statusResponse('registered'));
  assert.equal(await older, false);
  assert.equal(access.registered, false);
});

test('unconnected server never invents approval even with forged device flags', async () => {
  async function call(method, extra = {}) {
    const result = { headers: {} };
    const response = { setHeader(name, value) { result.headers[name] = value; },
      status(code) { result.status = code; return this; }, json(body) { result.body = body; return this; } };
    await handler({ method, headers: { origin: 'https://vault.vercel.app', host: 'vault.vercel.app',
      'content-type': 'application/json', 'x-device-registered': 'true' },
      body: { registered: true, approved: true, deviceId: 'untrusted' }, ...extra }, response);
    return result;
  }
  for (const method of ['GET', 'POST']) {
    const result = await call(method);
    assert.equal(result.status, 503);
    assert.equal(result.headers['Cache-Control'], 'no-store');
    assert.equal(result.body.registered, false);
    assert.equal(result.body.state, 'unavailable');
  }
  assert.equal((await call('DELETE')).status, 405);
  assert.equal((await call('POST', { headers: { origin: 'https://foreign.example' } })).status, 403);
});

const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
const inline = html.match(/<script type="module">([\s\S]*?)<\/script>/u)[1]
  .replace("const { createDeviceAccess } = await import('/device-access.js');", '');
const flush = async () => { for (let i = 0; i < 6; i++) await new Promise(done => setImmediate(done)); };

async function screen(state) {
  const requests = [];
  const elements = new Map();
  const events = new Map();
  function element() {
    return { hidden: true, value: '', textContent: '', children: [], callbacks: {},
      addEventListener(name, callback) { this.callbacks[name] = callback; },
      replaceChildren(...children) { this.children = children; },
      append(...children) { this.children.push(...children); }, reset() {}, focus() {} };
  }
  const document = { hidden: false, addEventListener(name, callback) { events.set(name, callback); },
    querySelector(selector) { if (!elements.has(selector)) elements.set(selector, element()); return elements.get(selector); },
    createElement: element };
  let deviceState = state;
  let releaseNote;
  let delayNotes = false;
  let rejectNote = false;
  const fetch = async (path, options) => {
    requests.push({ path, method: options?.method ?? 'GET' });
    if (path.startsWith('/api/auth')) return new Response(JSON.stringify({ session: path.includes('logout') ? null : session }));
    if (path === '/api/device-approval') return options.method === 'POST' ? statusResponse('registered') : statusResponse(deviceState);
    if (path === '/api/notes') {
      if (delayNotes) return new Promise(done => { releaseNote = () => done(new Response(JSON.stringify([{ id: 'fixture-note', title: 'fixture', body: 'private-fixture' }]))); });
      return new Response(JSON.stringify([{ id: 'fixture-note', title: 'fixture', body: 'private-fixture' }]));
    }
    if (path === '/api/notes/fixture-note') return rejectNote ? new Response('{}', { status: 403 })
      : new Response(JSON.stringify({ id: 'fixture-note', title: 'fixture', body: 'private-fixture' }));
    throw new Error('unexpected fixture request');
  };
  await vm.runInNewContext(`(async () => {${inline}})()`, {
    document, window: { addEventListener(name, callback) { events.set(name, callback); } },
    navigator: { onLine: true }, AbortController, fetch,
    createDeviceAccess: options => createDeviceAccess({ ...options, fetchStatus: fetch, schedule: () => 0 }),
  });
  await flush();
  return { requests, elements, events, state(value) { deviceState = value; },
    delay() { delayNotes = true; }, release() { releaseNote(); }, reject() { rejectNote = true; } };
}

test('actual screen fetches no notes before approval; approval request alone stays closed', async () => {
  const app = await screen('unregistered');
  assert.equal(app.requests.filter(request => request.path === '/api/notes').length, 0);
  assert.equal(app.elements.get('#notes').hidden, true);
  assert.equal(app.elements.get('#note-editor').hidden, true);
  assert.equal(app.elements.get('#notes').children.length, 0);
  app.elements.get('#request-device').callbacks.click();
  await flush();
  assert.equal(app.requests.filter(request => request.path === '/api/notes').length, 0);
  assert.equal(app.elements.get('#notes').hidden, true);
  app.state('registered');
  app.elements.get('#check-device').callbacks.click();
  await flush();
  assert.equal(app.elements.get('#notes').hidden, false);
  assert.equal(app.elements.get('#note-editor').hidden, false);
  assert.equal(app.elements.get('#notes').children[0].children[1].textContent, 'private-fixture');
  app.elements.get('#notes').children[0].children[3].callbacks.click();
  await flush();
  assert.equal(app.elements.get('#note-body').value, 'private-fixture');
  app.state('denied');
  app.elements.get('#check-device').callbacks.click();
  await flush();
  assert.equal(app.elements.get('#notes').hidden, true);
  assert.equal(app.elements.get('#notes').children.length, 0);
});

test('offline clears the screen and aborted late note responses cannot restore it', async () => {
  const app = await screen('registered');
  app.delay();
  app.elements.get('#check-device').callbacks.click();
  await flush();
  app.events.get('offline')();
  app.release();
  await flush();
  assert.equal(app.elements.get('#notes').hidden, true);
  assert.equal(app.elements.get('#notes').children.length, 0);
  assert.equal(app.elements.get('#note-editor').hidden, true);
});

test('protected API denial clears already visible notes and editor', async () => {
  const app = await screen('registered');
  app.reject();
  app.elements.get('#notes').children[0].children[3].callbacks.click();
  await flush();
  assert.equal(app.elements.get('#notes').hidden, true);
  assert.equal(app.elements.get('#notes').children.length, 0);
  assert.equal(app.elements.get('#note-editor').hidden, true);
});
