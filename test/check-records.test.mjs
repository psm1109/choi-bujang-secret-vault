import assert from 'node:assert/strict';
import { test } from 'node:test';
import { summarizeCheckRecords, createCheckRecordsHandler } from '../src/check-records.mjs';
import { createCheckRecordsPanel } from '../public/check-records.js';

const commit = 'a'.repeat(40);
const bundle = { schema: 'aleph.defense.submission.v2', commit, checkedAt: '2026-10-13T00:00:00.000Z',
  explanation: 'fixture_private_text', attackAttempts: [
    { attackId: 'deployment_config', stage: 5, expected: 'fixture_private_text', observed: 'HTTP 200', result: 'not_run', body: 'fixture_private_text' },
    { attackId: 'security_header', stage: 5, observed: 'HTTP 200', result: 'not_run' },
    { attackId: 'anonymous_note_list', stage: 3, observed: 'HTTP 401', result: 'blocked' },
    { attackId: 'anonymous_note_create', stage: 3, observed: 'not_run', result: 'not_run' },
  ] };
const response = () => ({ headers: {}, setHeader(name, value) { this.headers[name] = value; },
  status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } });

test('server summary counts its own redacted records and excludes content', () => {
  const report = summarizeCheckRecords(bundle, commit);
  assert.deepEqual([report.total, report.blocked, report.failed, report.notRun], [4, 1, 0, 3]);
  assert.deepEqual(report.records.map(item => Object.keys(item).sort()),
    Array.from({ length: 4 }, () => ['attackId', 'observed', 'result', 'stage']));
  assert.equal(JSON.stringify(report).includes('fixture_private_text'), false);
  assert.equal(report.records.filter(row => row.result === 'not_run').length, report.notRun);
});

test('missing, stale, duplicated and fabricated records remain unavailable', async () => {
  for (const invalid of [{ ...bundle, commit: 'b'.repeat(40) },
    { ...bundle, attackAttempts: [...bundle.attackAttempts, bundle.attackAttempts[0]] },
    { ...bundle, attackAttempts: [{ ...bundle.attackAttempts[0], observed: '막음' }] },
    { ...bundle, attackAttempts: [{ ...bundle.attackAttempts[0], result: 'blocked' }] },
    { ...bundle, attackAttempts: [{ attackId: 'anonymous_note_create', stage: 3, observed: 'HTTP 200', result: 'not_run' }] }]) {
    assert.throws(() => summarizeCheckRecords(invalid, commit));
  }
  const handler = createCheckRecordsHandler({ expectedCommit: commit, readBundle: async () => bundle });
  const okay = response(); await handler({ method: 'GET' }, okay);
  assert.equal(okay.code, 200);
  assert.equal(okay.headers['Cache-Control'], 'no-store');
  const wrongMethod = response(); await handler({ method: 'POST' }, wrongMethod);
  assert.equal(wrongMethod.code, 405);
  const absent = response();
  await createCheckRecordsHandler({ readBundle: async () => { throw new Error('private_fixture_text'); } })({ method: 'GET' }, absent);
  assert.equal(absent.code, 503);
  assert.equal(JSON.stringify(absent.body).includes('private_fixture_text'), false);
});

function panel(fetchRecords) {
  const node = () => ({ textContent: '', children: [], disabled: false,
    append(...values) { this.children.push(...values); }, replaceChildren(...values) { this.children = [...values]; },
    addEventListener() {} });
  const message = node(), content = node(), button = node();
  const root = { querySelector: selector => ({ '[data-check-message]': message,
    '[data-check-content]': content, button }[selector]),
    ownerDocument: { createElement: node, createDocumentFragment: node } };
  return { view: createCheckRecordsPanel({ root, fetchRecords }), message, content };
}

test('screen counts only blocked results and clears stale values on mismatch', async () => {
  let report = summarizeCheckRecords(bundle, commit);
  const { view, content, message } = panel(async () => new Response(JSON.stringify(report)));
  await view.refresh();
  assert.equal(content.children.length, 1);
  assert.equal(content.children[0].children[0].textContent,
    '점검 항목 4건 · 기대 조건 일치 1건 · 불일치 0건 · 미실행 3건');
  assert.equal(content.children[0].children[1].children.length, report.records.length);
  assert.ok(message.textContent.includes(commit));
  report = { ...report, blocked: 41 };
  await view.refresh();
  assert.equal(content.children.length, 0);
  assert.ok(message.textContent.includes('확인 불가'));
  await view.refresh();
  view.invalidate();
  assert.equal(content.children.length, 0);
});
