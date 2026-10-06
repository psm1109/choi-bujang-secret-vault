import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Script } from 'node:vm';
import handler from '../api/auth.js';

test('server login, refresh, logout and origin rejection keep keys off the browser', async () => {
  const oldFetch = globalThis.fetch;
  const oldUrl = process.env.SUPABASE_URL;
  const oldKey = process.env.SUPABASE_SECRET_KEY;
  let requests = [];
  let denied = false;
  const call = async (action, extra = {}) => {
    const result = { headers: {} };
    const response = {
      setHeader(name, value) { result.headers[name] = value; },
      status(code) { result.status = code; return this; },
      json(body) { result.body = body; return this; },
    };
    await handler({ method: 'POST', query: { action }, body: {},
      headers: { origin: 'https://vault.vercel.app', host: 'vault.vercel.app',
        'content-type': 'application/json' }, ...extra }, response);
    return result;
  };
  try {
    process.env.SUPABASE_URL = 'https://fixture.supabase.co';
    process.env.SUPABASE_SECRET_KEY = 'test-only-placeholder';
    globalThis.fetch = async (input, init) => {
      const url = new URL(input);
      requests.push({ url, init });
      assert.equal(new Headers(init.headers).get('apikey'), 'test-only-placeholder');
      if (url.pathname === '/auth/v1/logout') return new Response(null, { status: 204 });
      if (denied) return new Response(JSON.stringify({ error: 'invalid_grant' }), {
        status: 400, headers: { 'content-type': 'application/json' },
      });
      return new Response(JSON.stringify({ access_token: 'synthetic-access',
        refresh_token: 'synthetic-refresh', token_type: 'bearer', expires_in: 3600,
        user: { id: 'synthetic-user' } }), { headers: { 'content-type': 'application/json' } });
    };
    const forbidden = await call('login', { headers: { origin: 'https://foreign.example',
      host: 'vault.vercel.app', 'content-type': 'application/json' } });
    assert.equal(forbidden.status, 403);
    assert.equal(requests.length, 0);
    assert.equal((await call('login', { method: 'GET' })).status, 405);
    assert.equal((await call('login')).status, 400);
    assert.deepEqual((await call('session')).body, { session: null });
    const login = await call('login', { body: { email: 'synthetic', password: 'synthetic' } });
    assert.equal(login.status, 200);
    assert.equal(requests.at(-1).url.searchParams.get('grant_type'), 'password');
    assert.match(login.headers['Set-Cookie'], /HttpOnly; Secure; SameSite=Strict/);
    assert.equal(login.body.session.refresh_token, undefined);
    assert.equal(login.body.session.access_token, 'synthetic-access');
    const headers = { origin: 'https://vault.vercel.app', host: 'vault.vercel.app',
      'content-type': 'application/json', cookie: login.headers['Set-Cookie'].split(';')[0] };
    assert.equal((await call('session', { headers })).status, 200);
    assert.equal(requests.at(-1).url.searchParams.get('grant_type'), 'refresh_token');
    const logout = await call('logout', { headers });
    assert.equal(logout.status, 200);
    assert.match(logout.headers['Set-Cookie'], /Max-Age=0/);
    assert.equal(requests.at(-1).url.pathname, '/auth/v1/logout');
    assert.equal(requests.at(-1).url.searchParams.get('scope'), 'local');
    denied = true;
    assert.equal((await call('login', { body: { email: 'synthetic', password: 'synthetic' } })).status, 401);
    const expired = await call('session', { headers });
    assert.equal(expired.status, 401);
    assert.match(expired.headers['Set-Cookie'], /Max-Age=0/);
    delete process.env.SUPABASE_SECRET_KEY;
    assert.equal((await call('login')).status, 503);
    const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
    assert.doesNotMatch(html, /sb_publishable_|supabase|eyJ[A-Za-z0-9_-]+\./u);
    new Script(`(async () => {${html.match(/<script type="module">([\s\S]*?)<\/script>/u)[1]}})()`);
  } finally {
    globalThis.fetch = oldFetch;
    if (oldUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = oldUrl;
    if (oldKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = oldKey;
  }
});
