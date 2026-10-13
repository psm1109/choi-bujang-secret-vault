import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('bundle import graph uses only permitted builtins and local files', async () => {
  const allowed = new Set(['node:fs', 'node:path', 'node:url', 'node:child_process', 'node:crypto']);
  const visited = new Set();
  async function inspect(url) {
    if (visited.has(url.href)) return;
    visited.add(url.href);
    const source = await readFile(url, 'utf8');
    for (const match of source.matchAll(/(?:from\s*|import\s*\(\s*)['"]([^'"]+)['"]/gu)) {
      const specifier = match[1];
      if (specifier.startsWith('node:')) assert.ok(allowed.has(specifier), `unsupported builtin: ${specifier}`);
      else {
        assert.ok(specifier.startsWith('.'), 'bundle must not import npm packages');
        await inspect(new URL(specifier, url));
      }
    }
  }
  await inspect(new URL('../scripts/bundle.mjs', import.meta.url));
  // bundle.mjs는 이 두 진입점을 URL 변수로 동적 import합니다.
  await inspect(new URL('../src/attack-check.mjs', import.meta.url));
  await inspect(new URL('../src/decider.mjs', import.meta.url));
});

test('bundle checks across supported stages send only read requests and never mark writes executed', async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const step of [1, 3, 4, 5, 6, 7, 8, 9, 10, 11]) {
      const attempts = [];
      globalThis.fetch = async (input, init) => {
        const url = new URL(input);
        attempts.push({ method: init.method ?? 'GET', body: init.body, protocol: url.protocol });
        return new Response('{}', { status: 401 });
      };
      const results = await runAttackChecks({ ...config, step,
        originalApiUrl: 'https://student.supabase.co/rest/v1/learning_notes',
        allowedRoutes: ['GET /api/notes/:id'], restoreRoute: '/api/notes/restore' });
      assert.ok(attempts.length > 0);
      assert.ok(attempts.every(item => ['GET', 'HEAD'].includes(item.method)
        && item.body === undefined && item.protocol === 'https:'));
      for (const item of results.filter(item => ['anonymous_note_create', 'anonymous_note_update',
        'anonymous_note_delete', 'restore_backup_verification', 'device_request_endpoint', 'detection_fixtures'].includes(item.attackId))) {
        assert.equal(item.observed, 'not_run');
      }
    }
  } finally { globalThis.fetch = originalFetch; }
});

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.equal(deploymentIdentity(env, { ...config, step: 3 }).step, 3);
  assert.equal(deploymentIdentity(env, { ...config, step: 4 }).step, 4);
  const stage5 = { ...config, step: 5,
    originalApiUrl: 'https://student.supabase.co/rest/v1/learning_notes' };
  assert.equal(deploymentIdentity(env, stage5).originalApiUrl, stage5.originalApiUrl);
  assert.throws(() => deploymentIdentity(env, { ...stage5, originalApiUrl: undefined }));
  assert.throws(() => deploymentIdentity(env, {
    ...stage5, originalApiUrl: `${stage5.originalApiUrl}?select=id`,
  }));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('stage 9 bundle keeps unsupported detection practice unexecuted and results bounded', async () => {
  const originalFetch = globalThis.fetch;
  const config9 = { ...config, step: 9,
    originalApiUrl: 'https://student.supabase.co/rest/v1/learning_notes',
    allowedRoutes: ['GET /api/notes/:id', 'PUT /api/notes/:id'] };
  let requests = 0;
  try {
    globalThis.fetch = async (input, init) => {
      requests += 1;
      assert.equal(new Headers(init.headers).has('authorization'), false);
      const path = new URL(input).pathname;
      if (path === '/aleph.json') return new Response(JSON.stringify({ ...config9, step: 8 }));
      if (path === '/') return new Response('<html></html>', { headers: { 'x-content-type-options': 'nosniff' } });
      return new Response('fixture_body_should_not_be_recorded', { status: path === '/data.json' ? 404 : 401 });
    };
    const results = await runAttackChecks(config9);
    assert.equal(requests, 6);
    assert.equal(results.length, 19);
    assert.equal(new Set(results.map(item => item.attackId)).size, results.length);
    assert.match(results.find(item => item.attackId === 'deployment_config').observed, /설정 불일치/u);
    assert.match(results.find(item => item.attackId === 'resource_zone_fixtures').observed, /read:allow, update:allow, list:deny/u);
    assert.equal(results.find(item => item.attackId === 'detection_fixtures').observed, 'not_run');
    assert.match(results.find(item => item.attackId === 'revocation_and_timing').observed, /^미실행;/u);
    const serialized = JSON.stringify(results);
    for (const value of ['fixture_body_should_not_be_recorded', 'learner_fixture', 'aaaaaaaaaaaaaaaa']) {
      assert.equal(serialized.includes(value), false);
    }
    for (const item of results) {
      assert.deepEqual(Object.keys(item).sort(), ['attackId', 'expected', 'observed']);
      assert.ok(item.expected.length <= 300 && item.observed.length <= 300);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('stage 10 bundle sends no restore request and marks recovery not_run', async () => {
  const originalFetch = globalThis.fetch;
  const config10 = { ...config, step: 10, restoreRoute: '/api/notes/restore',
    originalApiUrl: 'https://student.supabase.co/rest/v1/learning_notes', allowedRoutes: ['GET /api/notes/:id'] };
  let restoreRequests = 0;
  try {
    globalThis.fetch = async (input, init) => {
      assert.equal(new Headers(init.headers).has('authorization'), false);
      const path = new URL(input).pathname;
      if (path === '/aleph.json') return new Response(JSON.stringify(config10));
      if (path === '/') return new Response('<html></html>', { headers: { 'x-content-type-options': 'nosniff' } });
      if (path === config10.restoreRoute) {
        restoreRequests++;
      }
      return new Response('private_fixture_not_recorded', { status: path === '/data.json' ? 404 : 401 });
    };
    const results = await runAttackChecks(config10);
    assert.equal(results.length, 20);
    assert.equal(restoreRequests, 0);
    const restore = results.find(item => item.attackId === 'restore_backup_verification');
    assert.equal(restore.observed, 'not_run');
    assert.equal(JSON.stringify(results).includes('private_fixture_not_recorded'), false);
    assert.ok(results.every(item => item.observed.length <= 300));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('stage 11 bundle reports only supported HTTP evidence and marks every other check not_run', async () => {
  const originalFetch = globalThis.fetch;
  const config11 = { ...config, step: 11, restoreRoute: '/api/notes/restore',
    originalApiUrl: 'https://student.supabase.co/rest/v1/learning_notes', allowedRoutes: ['GET /api/notes/:id'] };
  const calls = [];
  try {
    globalThis.fetch = async (input, init) => {
      const url = new URL(input);
      calls.push([url.pathname, init.method ?? 'GET', init.alephEvidence]);
      assert.equal(new Headers(init.headers).has('authorization'), false);
      if (url.pathname === '/aleph.json') return new Response(JSON.stringify({ ...config11, step: 10 }));
      if (url.pathname === '/') return new Response('<html></html>', { headers: { 'x-content-type-options': 'nosniff' } });
      if (url.pathname === '/manifest.webmanifest') return new Response(JSON.stringify({
        name: '최 부장 비밀 자료실', start_url: '/', display: 'standalone',
        icons: [192, 512].map(size => ({ src: `/icons/vault-${size}.png`, sizes: `${size}x${size}` })),
      }));
      if (url.pathname === '/api/device-approval') {
        return new Response(JSON.stringify({ schema: 'aleph.device-access.v1', state: 'unavailable', registered: false }), { status: 503 });
      }
      return new Response('private_fixture_not_recorded', { status: url.pathname === '/data.json' ? 404 : 401 });
    };
    const results = await runAttackChecks(config11);
    assert.deepEqual(calls, [
      ['/aleph.json', 'GET', { caseId: 'deployment_config', requestKey: 'read' }],
      ['/', 'GET', { caseId: 'security_header', requestKey: 'read' }],
      ['/', 'GET', { caseId: 'browser_public_key', requestKey: 'read' }],
    ]);
    assert.equal(results.length, 19);
    assert.equal(new Set(results.map(item => item.attackId)).size, 19);
    const executed = results.filter(item => item.observed !== 'not_run');
    assert.deepEqual(executed.map(item => item.attackId), ['deployment_config', 'security_header', 'browser_public_key']);
    assert.ok(executed.every(item => item.observed === 'HTTP 200'));
    assert.deepEqual(executed.map(item => item.result), ['breached', 'blocked', 'blocked']);
    assert.equal(results.filter(item => item.observed === 'not_run').length, 16);
    for (const item of results) {
      assert.deepEqual(Object.keys(item).sort(), ['attackId', 'expected', 'observed', 'result', 'stage']);
      assert.ok(item.expected.length <= 300 && item.observed.length <= 300);
    }
    assert.equal(JSON.stringify(results).includes('private_fixture_not_recorded'), false);
  } finally { globalThis.fetch = originalFetch; }
});

test('stage 11 missing HTTP evidence never creates executed results or synthetic attack IDs', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => { throw new Error('fixture_network_failure'); };
    const results = await runAttackChecks({ ...config, step: 11 });
    assert.equal(results.length, 19);
    assert.ok(results.every(item => item.observed === 'not_run'));
    assert.equal(new Set(results.map(item => item.attackId)).size, 19);
    assert.equal(results.some(item => item.attackId === 'first_page_checks'), false);
  } finally { globalThis.fetch = originalFetch; }
});

test('build identity accepts stages 6 through 12 and rejects invalid stages', () => {
  const laterStage = { ...config,
    originalApiUrl: 'https://student.supabase.co/rest/v1/learning_notes',
    allowedRoutes: ['GET /api/notes'] };
  for (let step = 6; step <= 12; step += 1) {
    const identity = deploymentIdentity(env, { ...laterStage, step });
    assert.equal(identity.step, step);
    assert.equal(identity.originalApiUrl, laterStage.originalApiUrl);
    assert.deepEqual(identity.allowedRoutes, laterStage.allowedRoutes);
    assert.throws(() => deploymentIdentity(env, {
      ...laterStage, step, originalApiUrl: undefined,
    }));
  }
  for (const step of [0, 13, 6.5, '6']) {
    assert.throws(() => deploymentIdentity(env, { ...laterStage, step }));
  }
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' },
    { ...laterStage, step: 6 }));
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.equal(options.redirect, 'error');
    assert.match(result.observed, /확인 표시가 보임/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('stage 8 bundle checks record actual HTTP statuses and separate bounded local zone practice', async () => {
  const originalFetch = globalThis.fetch;
  const config8 = { ...config, step: 8,
    originalApiUrl: 'https://student.supabase.co/rest/v1/learning_notes',
    allowedRoutes: ['GET /api/notes/:id', 'PUT /api/notes/:id'] };
  let actualRequests = 0;
  try {
    globalThis.fetch = async (input, init) => {
      actualRequests++;
      assert.equal(new Headers(init.headers).has('authorization'), false);
      const path = new URL(input).pathname;
      if (path === '/aleph.json') return new Response(JSON.stringify({ ...config8, commit: 'a'.repeat(40) }));
      if (path === '/') return new Response('<html></html>', { headers: { 'x-content-type-options': 'nosniff' } });
      return new Response('{}', { status: path === '/data.json' ? 404 : 401 });
    };
    const results = await runAttackChecks(config8);
    assert.equal(actualRequests, 6);
    assert.ok(results.length <= 20);
    assert.ok(results.filter(item => ['anonymous_note_list', 'anonymous_shared_read', 'anonymous_note_read'].includes(item.attackId))
      .every(item => item.observed.includes('HTTP 401')));
    assert.ok(results.filter(item => ['anonymous_note_create', 'anonymous_note_update', 'anonymous_note_delete'].includes(item.attackId))
      .every(item => item.observed === 'not_run'));
    const zones = results.find(item => item.attackId === 'resource_zone_fixtures');
    assert.ok(zones);
    assert.ok(!zones.observed.includes('불일치'));
    assert.match(zones.observed, /read:allow, update:allow, list:deny/u);
    assert.match(zones.observed, /post:deny, put:deny, patch:deny, delete:deny/u);
    assert.equal(results.find(item => item.attackId === 'cross_owner_access').observed,
      '미실행; 실제 계정·DB 정책 시험 및 심판 판정 미확인');
    for (const item of results) assert.ok(item.observed.length <= 300);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
