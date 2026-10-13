import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('../public/app-shell.js', import.meta.url), 'utf8');
const worker = await readFile(new URL('../public/sw.js', import.meta.url), 'utf8');

function app() {
  const events = new Map();
  const elements = new Map();
  const navigator = { onLine: true };
  const standalone = { matches: false, addEventListener() {} };
  const window = { matchMedia: () => standalone,
    addEventListener: (name, callback) => events.set(name, callback) };
  const document = { querySelector: selector => {
    if (!elements.has(selector)) elements.set(selector, {
      hidden: selector === '#install-app', textContent: '',
      addEventListener(name, callback) { this[name] = callback; },
    });
    return elements.get(selector);
  } };
  // Storage APIs and fetch are deliberately absent: display must not depend on them.
  vm.runInNewContext(source, { window, navigator, document });
  return { events, elements, navigator, standalone };
}

test('installation, standalone and offline never report device approval', async () => {
  const { events, elements, navigator } = app();
  const device = elements.get('#device-status');
  assert.match(device.textContent, /기기 승인: 확인 불가/u);
  events.get('beforeinstallprompt')({ preventDefault() {}, prompt: async () => {},
    userChoice: Promise.resolve({ outcome: 'accepted' }) });
  assert.equal(elements.get('#install-app').hidden, false);
  await elements.get('#install-app').click();
  assert.match(device.textContent, /기기 승인: 확인 불가/u);
  events.get('appinstalled')();
  assert.match(elements.get('#install-status').textContent, /확인이 완료된 것은 아닙니다/u);
  assert.match(device.textContent, /기기 승인: 확인 불가/u);
  navigator.onLine = false;
  events.get('offline')();
  assert.match(device.textContent, /확인 불가.*오프라인/u);
  assert.equal(elements.get('#offline-notice').hidden, false);
  navigator.onLine = true;
  events.get('online')();
  assert.match(device.textContent, /확인 불가.*연결이 제공되지/u);
  assert.equal(elements.get('#offline-notice').hidden, true);
  const installed = app();
  installed.standalone.matches = true;
  installed.events.get('beforeinstallprompt')({ preventDefault() {} });
  assert.equal(installed.elements.get('#install-app').hidden, true);
  assert.match(installed.elements.get('#device-status').textContent, /확인 불가/u);
});

function serviceWorker(fetch) {
  const events = new Map();
  const stored = new Map();
  const deleted = [];
  const cache = { put: async (path, response) => stored.set(path, response),
    match: async path => stored.get(path) };
  vm.runInNewContext(worker, { URL, Response, fetch,
    caches: { open: async () => cache, keys: async () => ['vault-offline-v0', 'other-app'],
      delete: async key => deleted.push(key) },
    self: { location: { origin: 'https://vault.example' }, skipWaiting: async () => {},
      clients: { claim: async () => {} }, addEventListener: (name, callback) => events.set(name, callback) },
  });
  return { events, stored, deleted };
}

test('worker caches only the public offline notice and leaves API requests untouched', async () => {
  const offline = new Response('public offline notice');
  const sw = serviceWorker(async (path, options) => {
    assert.equal(path, '/offline.html');
    assert.equal(options.credentials, 'omit');
    return offline;
  });
  let task;
  sw.events.get('install')({ waitUntil: promise => { task = promise; } });
  await task;
  assert.deepEqual([...sw.stored.keys()], ['/offline.html']);
  sw.events.get('activate')({ waitUntil: promise => { task = promise; } });
  await task;
  assert.deepEqual(sw.deleted, ['vault-offline-v0']);
  for (const [path, mode, method] of [
    ['/api/auth?action=session', 'cors', 'POST'], ['/api/notes', 'cors', 'GET'],
    ['/api/notes', 'navigate', 'GET'], ['/api/notes/restore', 'cors', 'POST'],
    ['/data.json', 'navigate', 'GET'], ['/', 'navigate', 'POST'],
    ['https://other.example/', 'navigate', 'GET'],
  ]) {
    sw.events.get('fetch')({ request: { url: new URL(path, 'https://vault.example').href, mode, method },
      respondWith() { assert.fail(`Intercepted protected/non-app request: ${path}`); } });
  }
});

test('navigation preserves HTTP rejection and falls back only on network failure', async () => {
  for (const status of [200, 401, 403, 404, 503]) {
    const response = new Response('network result', { status });
    const sw = serviceWorker(async () => response);
    let result;
    sw.events.get('fetch')({ request: { url: 'https://vault.example/', method: 'GET', mode: 'navigate' },
      respondWith(promise) { result = promise; } });
    assert.equal(await result, response);
    assert.equal(sw.stored.size, 0);
  }
  const sw = serviceWorker(async () => { throw new TypeError('offline'); });
  const notice = new Response('public offline notice');
  sw.stored.set('/offline.html', notice);
  let result;
  sw.events.get('fetch')({ request: { url: 'https://vault.example/', method: 'GET', mode: 'navigate' },
    respondWith(promise) { result = promise; } });
  assert.equal(await result, notice);
});

test('manifest icons exist at their declared PNG dimensions', async () => {
  const manifest = JSON.parse(await readFile(new URL('../public/manifest.webmanifest', import.meta.url)));
  assert.equal(manifest.start_url, '/');
  assert.equal(manifest.scope, '/');
  for (const icon of manifest.icons) {
    const png = await readFile(new URL(`../public${icon.src}`, import.meta.url));
    assert.equal(png.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
    assert.equal(icon.sizes, `${png.readUInt32BE(16)}x${png.readUInt32BE(20)}`);
  }
});
