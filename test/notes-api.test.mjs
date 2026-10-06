import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { readFileSync } from 'node:fs';
import handler from '../api/notes.js';

test('notes API exposes only notes and keeps configuration and DB errors private', async () => {
  const originalFetch = globalThis.fetch;
  const originalUrl = process.env.SUPABASE_URL;
  const originalKey = process.env.SUPABASE_SECRET_KEY;
  const call = async (method = 'GET', authorization, extra = {}) => {
    const result = { headers: {} };
    const response = {
      setHeader(name, value) { result.headers[name] = value; },
      status(code) { result.status = code; return this; },
      json(body) { result.body = body; return this; },
    };
    await handler({ method, headers: { authorization }, ...extra }, response);
    return result;
  };
  try {
    const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url)));
    process.env.SUPABASE_URL = new URL(config.identityProvider.issuer).origin;
    const { publicKey, privateKey } = await generateKeyPair('ES256');
    const jwk = { ...await exportJWK(publicKey), kid: 'notes-test', alg: 'ES256' };
    const sign = (claims = {}, key = privateKey) => new SignJWT({ role: 'authenticated', ...claims })
      .setProtectedHeader({ alg: 'ES256', kid: 'notes-test' })
      .setIssuer(claims.iss ?? config.identityProvider.issuer)
      .setAudience(claims.aud ?? config.identityProvider.audience)
      .setSubject('00000000-0000-4000-8000-000000000001')
      .setIssuedAt().setExpirationTime(claims.exp ?? '5m').sign(key);
    const authorization = `Bearer ${await sign()}`;
    process.env.SUPABASE_SECRET_KEY = 'test-only-placeholder';
    let calls = 0;
    const notes = Array.from({ length: 4 }, (_, i) => ({ title: `Test ${i}`, content: `Fixture ${i}` }));
    globalThis.fetch = async (input, options) => {
      const url = new URL(input);
      if (url.pathname.endsWith('/.well-known/jwks.json')) {
        return new Response(JSON.stringify({ keys: [jwk] }), { headers: { 'content-type': 'application/json' } });
      }
      calls++;
      assert.equal(url.pathname, '/rest/v1/learning_notes');
      assert.equal(url.searchParams.get('select'), 'title,content');
      assert.equal(new Headers(options.headers).get('apikey'), 'test-only-placeholder');
      return new Response(JSON.stringify(notes.map(note => ({ ...note, owner_id: 'excluded' }))), {
        headers: { 'content-type': 'application/json' },
      });
    };
    for (const token of [undefined, 'Bearer invalid', `Bearer ${await sign({ iss: 'https://other.supabase.co/auth/v1' })}`,
      `Bearer ${await sign({ exp: Math.floor(Date.now() / 1000) - 60 })}`,
      `Bearer ${await sign({ aud: 'other' })}`, `Bearer ${await sign({ role: 'anon' })}`,
      `Bearer ${await sign({}, (await generateKeyPair('ES256')).privateKey)}`]) {
      const denied = await call('GET', token, { query: { userId: 'forged', role: 'authenticated' }, body: { role: 'judge' } });
      assert.equal(denied.status, 401);
      assert.deepEqual(denied.body, { error: 'UNAUTHORIZED' });
    }
    assert.equal(calls, 0, 'rejected requests must not query notes');
    const success = await call('GET', authorization);
    assert.equal(success.status, 200);
    assert.equal(success.headers['Cache-Control'], 'no-store');
    assert.deepEqual(success.body, { notes });
    assert.equal((await call('POST')).status, 405);
    assert.equal(calls, 1);
    const judgeA = await new SignJWT({ aleph_role: 'judge', aleph_identity: 'a',
      aleph_run: '00000000-0000-4000-8000-000000000002' })
      .setProtectedHeader({ alg: 'ES256', kid: 'notes-test' })
      .setIssuer(config.judgeIssuer).setAudience(new URL(config.publicAppUrl).hostname)
      .setSubject('00000000-0000-4000-8000-000000000001')
      .setIssuedAt().setExpirationTime('5m').sign(privateKey);
    const judgeSuccess = await call('GET', `Bearer ${judgeA}`);
    assert.equal(judgeSuccess.status, 200);
    assert.deepEqual(judgeSuccess.body, { notes });
    globalThis.fetch = async () => new Response(JSON.stringify({ message: 'test-only-placeholder' }), {
      status: 403, headers: { 'content-type': 'application/json' },
    });
    const failure = await call('GET', authorization);
    assert.equal(failure.status, 503);
    assert.deepEqual(failure.body, { error: 'NOTES_UNAVAILABLE' });
    delete process.env.SUPABASE_SECRET_KEY;
    globalThis.fetch = async () => { throw new Error('must not connect'); };
    assert.equal((await call('GET', authorization)).status, 503);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = originalUrl;
    if (originalKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = originalKey;
  }
});
