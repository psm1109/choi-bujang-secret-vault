import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { readFileSync } from 'node:fs';
import handler from '../api/notes.js';

test('A can manage notes while anonymous requests are denied and existing shared notes remain readable', async () => {
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
    const ownerA = '00000000-0000-4000-8000-000000000001';
    const ownerB = '00000000-0000-4000-8000-000000000003';
    const sharedId = '00000000-0000-4000-8000-000000000009';
    const sharedNote = { id: sharedId, title: 'Shared fixture', content: 'Synthetic shared fixture', owner_id: null };
    const rows = new Map([[sharedId, sharedNote]]);
    const notes = [];
    let dbFailure = false;
    globalThis.fetch = async (input, options) => {
      const url = new URL(input);
      if (url.pathname.endsWith('/.well-known/jwks.json')) {
        return new Response(JSON.stringify({ keys: [jwk] }), { headers: { 'content-type': 'application/json' } });
      }
      calls++;
      assert.equal(url.pathname, '/rest/v1/learning_notes');
      assert.equal(new Headers(options.headers).get('apikey'), 'test-only-placeholder');
      if (dbFailure) return new Response(JSON.stringify({ message: 'private database error' }), {
        status: 503, headers: { 'content-type': 'application/json' },
      });
      const id = url.searchParams.get('id')?.slice(3);
      let result;
      if (options.method === 'POST') {
        const row = JSON.parse(options.body);
        assert.equal(row.owner_id, ownerA);
        if (rows.has(row.id)) return new Response(JSON.stringify({ code: '23505' }), { status: 409 });
        rows.set(row.id, row); result = null;
      } else if (options.method === 'PATCH') {
        const row = rows.get(id);
        const payload = JSON.parse(options.body);
        assert.equal('owner_id' in payload, false);
        if (row) Object.assign(row, payload);
        result = row ? [row] : [];
      } else if (options.method === 'DELETE') {
        result = rows.has(id) ? [{ id }] : [];
        rows.delete(id);
      } else if (id) {
        result = rows.has(id) ? [rows.get(id)] : [];
      } else {
        const owner = url.searchParams.get('owner_id');
        assert.ok(owner === `eq.${ownerA}` || owner === `eq.${ownerB}` || owner === 'is.null');
        result = [...rows.values()].filter(row => owner === 'is.null' ? row.owner_id === null : `eq.${row.owner_id}` === owner);
      }
      return new Response(JSON.stringify(result), { headers: { 'content-type': 'application/json' } });
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
    assert.deepEqual(success.body, notes);
    assert.equal((await call('POST')).status, 401);
    assert.equal((await call('PATCH')).status, 405);
    assert.equal(calls, 1);
    const judgeA = await new SignJWT({ aleph_role: 'judge', aleph_identity: 'a',
      aleph_run: '00000000-0000-4000-8000-000000000002' })
      .setProtectedHeader({ alg: 'ES256', kid: 'notes-test' })
      .setIssuer(config.judgeIssuer).setAudience(new URL(config.publicAppUrl).hostname)
      .setSubject('00000000-0000-4000-8000-000000000001')
      .setIssuedAt().setExpirationTime('5m').sign(privateKey);
    const judgeSuccess = await call('GET', `Bearer ${judgeA}`);
    assert.equal(judgeSuccess.status, 200);
    assert.deepEqual(judgeSuccess.body, notes);
    const post = await call('POST', authorization, { body: {
      title: 'Synthetic title', body: 'Synthetic fixture', owner_id: ownerB, userId: ownerB,
    } });
    assert.equal(post.status, 201);
    const id = post.body.id;
    assert.match(id, /^[0-9a-f-]{36}$/);
    assert.equal(rows.get(id).owner_id, ownerA);
    const single = await call('GET', authorization, { query: { id } });
    assert.deepEqual(single.body, { id, title: 'Synthetic title', body: 'Synthetic fixture' });
    assert.deepEqual((await call('GET', authorization)).body, [single.body]);
    assert.equal((await call('POST', authorization, { body: { id, title: 'Duplicate', body: '' } })).status, 409);
    assert.equal((await call('POST', authorization, { body: { id: 'invalid', title: 'Title', body: '' } })).status, 400);
    const suppliedId = '00000000-0000-4000-8000-000000000004';
    assert.deepEqual((await call('POST', authorization, { body: { id: suppliedId, title: 'Provided', body: '' } })).body, { id: suppliedId });
    const changed = await call('PUT', authorization, { query: { id }, body: {
      title: 'Changed by A', body: 'Updated synthetic fixture', owner_id: ownerB,
    } });
    assert.equal(changed.status, 200);
    assert.deepEqual(changed.body, { id, title: 'Changed by A', body: 'Updated synthetic fixture' });
    assert.equal(rows.get(id).owner_id, ownerA);
    for (const method of ['GET', 'PUT', 'DELETE']) {
      const denied = await call(method, undefined, { query: { id }, body: { title: 'Denied', body: '' } });
      assert.equal(denied.status, 401);
      assert.deepEqual(denied.body, { error: 'UNAUTHORIZED' });
    }
    assert.equal((await call('GET', authorization, { query: { id } })).body.title, 'Changed by A');
    assert.equal((await call('DELETE', authorization, { query: { id } })).status, 200);
    assert.equal((await call('GET', authorization, { query: { id } })).status, 404);
    assert.equal((await call('PUT', authorization, { query: { id }, body: { title: 'Gone', body: '' } })).status, 404);
    assert.equal((await call('DELETE', authorization, { query: { id } })).status, 404);
    const shared = await call('GET', authorization, { query: { scope: 'shared' } });
    assert.equal(shared.status, 200);
    assert.deepEqual(shared.body, [{ id: sharedId, title: sharedNote.title, body: sharedNote.content }]);
    assert.equal((await call('GET', undefined, { query: { scope: 'shared' } })).status, 401);
    dbFailure = true;
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
