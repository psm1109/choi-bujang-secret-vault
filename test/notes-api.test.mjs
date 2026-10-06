import assert from 'node:assert/strict';
import { test } from 'node:test';
import handler from '../api/notes.js';

test('notes API exposes only notes and keeps configuration and DB errors private', async () => {
  const originalFetch = globalThis.fetch;
  const originalUrl = process.env.SUPABASE_URL;
  const originalKey = process.env.SUPABASE_SECRET_KEY;
  const call = async (method = 'GET') => {
    const result = { headers: {} };
    const response = {
      setHeader(name, value) { result.headers[name] = value; },
      status(code) { result.status = code; return this; },
      json(body) { result.body = body; return this; },
    };
    await handler({ method }, response);
    return result;
  };
  try {
    process.env.SUPABASE_URL = 'https://database.example';
    process.env.SUPABASE_SECRET_KEY = 'test-only-placeholder';
    let calls = 0;
    const notes = Array.from({ length: 4 }, (_, i) => ({ title: `Test ${i}`, content: `Fixture ${i}` }));
    globalThis.fetch = async (input, options) => {
      calls++;
      const url = new URL(input);
      assert.equal(url.pathname, '/rest/v1/learning_notes');
      assert.equal(url.searchParams.get('select'), 'title,content');
      assert.equal(new Headers(options.headers).get('apikey'), 'test-only-placeholder');
      return new Response(JSON.stringify(notes.map(note => ({ ...note, owner_id: 'excluded' }))), {
        headers: { 'content-type': 'application/json' },
      });
    };
    const success = await call();
    assert.equal(success.status, 200);
    assert.equal(success.headers['Cache-Control'], 'no-store');
    assert.deepEqual(success.body, { notes });
    assert.equal((await call('POST')).status, 405);
    assert.equal(calls, 1);
    globalThis.fetch = async () => new Response(JSON.stringify({ message: 'test-only-placeholder' }), {
      status: 403, headers: { 'content-type': 'application/json' },
    });
    const failure = await call();
    assert.equal(failure.status, 503);
    assert.deepEqual(failure.body, { error: 'NOTES_UNAVAILABLE' });
    delete process.env.SUPABASE_SECRET_KEY;
    globalThis.fetch = async () => { throw new Error('must not connect'); };
    assert.equal((await call()).status, 503);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = originalUrl;
    if (originalKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = originalKey;
  }
});
