import assert from 'node:assert/strict';
import { test } from 'node:test';
import { operationsSnapshot, createOperationsHandler } from '../src/operations.mjs';
import { createOperationsPanel } from '../public/operations.js';
import { RULE_IDS } from '../src/decider.mjs';

const at = '2026-10-01T00:00:00.000Z';
const now = new Date('2026-10-02T00:00:00.000Z');
const record = (kind, outcome, extras = {}) => ({ source: 'actual_api', kind, outcome, at, httpStatus: 200, ...extras });
const records = [record('decision', 'allow', { ruleIds: ['notes_read'] }),
  record('decision', 'deny', { ruleIds: ['device_registered'] }),
  record('detection', 'propose_revocation'), record('revocation', 'failed', { httpStatus: 503 }),
  record('recovery', 'restored', { versionVerified: true, versionSha256: 'a'.repeat(64) })];
function response() {
  return { headers: {}, setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.code = code; return this; }, json(value) { this.body = value; return this; } };
}

test('missing operational connection stays unexecuted; implemented rules are not successful decisions', () => {
  const report = operationsSnapshot(null, now);
  assert.equal(report.connected, false);
  assert.deepEqual(report.rules, [...RULE_IDS]);
  assert.deepEqual(report.records, []);
  for (const section of Object.values(report.summary)) {
    assert.equal(section.state, 'not_run');
    assert.equal(section.total, null);
    assert.ok(Object.values(section.counts).every(count => count === null));
  }
  assert.equal(operationsSnapshot([], now).connected, true);
  assert.equal(operationsSnapshot([], now).summary.revocation.total, null);
});

test('summaries match only returned redacted records; proposal does not count as completed revocation', () => {
  const report = operationsSnapshot(records.map(row => ({ ...row,
    body: 'fixture-private-marker', title: 'fixture-private-marker', access_token: 'fixture-private-marker',
    subjectId: 'fixture-private-marker', deviceId: 'fixture-private-marker' })), now);
  assert.equal(JSON.stringify(report).includes('fixture-private-marker'), false);
  for (const [kind, section] of Object.entries(report.summary)) {
    const rows = report.records.filter(row => row.kind === kind);
    assert.equal(section.total, rows.length);
    assert.equal(Object.values(section.counts).reduce((a, b) => a + b, 0), rows.length);
  }
  assert.equal(report.summary.revocation.counts.revoked, 0);
  assert.equal(report.summary.detection.counts.propose_revocation, 1);
  assert.equal(report.records.at(-1).versionSha256, 'a'.repeat(64));
});

test('local results, invalid timestamps, unknown rules and unverified recovery are rejected', () => {
  for (const row of [record('detection', 'observe', { source: 'fixture' }),
    record('detection', 'observe', { at: '2026-02-30T00:00:00.000Z' }),
    record('detection', 'observe', { at: '2030-01-01T00:00:00.000Z' }),
    record('revocation', 'revoked', { httpStatus: 503 }),
    record('decision', 'allow', { ruleIds: ['invented-rule'] }),
    record('recovery', 'restored', { versionSha256: 'a'.repeat(64) }),
    record('recovery', 'restored', { versionVerified: true, versionSha256: 'arbitrary-text' })]) {
    assert.throws(() => operationsSnapshot([row], now));
  }
});

test('API enforces verified login and GET; browser body/query never supply evidence', async () => {
  let reads = 0;
  const handler = createOperationsHandler({ verifyLogin: async value => value === 'fixture-valid',
    loadRecords: async () => { reads++; return null; } });
  for (const [request, status] of [ [{ method: 'POST' }, 405],
    [{ method: 'GET', headers: {} }, 401],
    [{ method: 'GET', headers: { authorization: 'fixture-invalid' } }, 401] ]) {
    const result = response(); await handler(request, result); assert.equal(result.code, status);
  }
  assert.equal(reads, 0);
  const result = response();
  await handler({ method: 'GET', headers: { authorization: 'fixture-valid' }, body: records, query: { records } }, result);
  assert.equal(result.code, 200);
  assert.deepEqual(result.body.records, []);
  assert.equal(result.headers['Cache-Control'], 'no-store');
  const unavailable = createOperationsHandler({ verifyLogin: async () => true,
    loadRecords: async () => [record('recovery', 'restored')] });
  const failure = response(); await unavailable({ method: 'GET', headers: { authorization: 'fixture-valid' } }, failure);
  assert.equal(failure.code, 503);
  assert.deepEqual(failure.body, { error: 'OPERATIONS_UNAVAILABLE' });
});

// 작은 DOM 대역으로 숫자 대조·오류·로그아웃·늦은 응답 폐기를 확인합니다.
function panel(fetchReport) {
  const node = () => ({ textContent: '', children: [], disabled: false,
    append(...values) { this.children.push(...values); },
    replaceChildren(...values) { this.children = [...values]; }, addEventListener() {} });
  const message = node(), content = node(), button = node();
  const root = { querySelector: name => ({ '[data-message]': message, '[data-content]': content, button }[name]),
    ownerDocument: { createElement: node, createDocumentFragment: node } };
  return { controller: createOperationsPanel({ root, fetchReport, online: () => true }), message, content, button };
}
const session = { access_token: 'fixture-in-memory' };
test('screen matches masked records and refuses mismatched server summary without stale success', async () => {
  let report = operationsSnapshot(records, now);
  const { controller, content, message, button } = panel(async () => new Response(JSON.stringify(report)));
  controller.setSession(session);
  await controller.refresh();
  assert.equal(content.children.length, 1);
  assert.ok(message.textContent.includes('반환된 기록'));
  report.summary.revocation.counts.revoked = 41;
  await controller.refresh();
  assert.equal(content.children.length, 0);
  assert.ok(message.textContent.includes('일치하지'));
  assert.equal(button.disabled, false);
  report = operationsSnapshot(records, now);
  delete report.summary.decision.counts.deny;
  await controller.refresh();
  assert.equal(content.children.length, 0);
});

test('logout/offline discard records and delayed responses', async () => {
  let finish;
  const { controller, content, button } = panel(() => new Promise(resolve => { finish = resolve; }));
  controller.setSession(session);
  const pending = controller.refresh();
  controller.setSession(null);
  finish(new Response(JSON.stringify(operationsSnapshot(records, now))));
  await pending;
  assert.equal(content.children.length, 0);
  assert.equal(button.disabled, true);
  controller.setSession(session);
  const offlinePending = controller.refresh();
  controller.invalidate();
  finish(new Response(JSON.stringify(operationsSnapshot(records, now))));
  await offlinePending;
  assert.equal(content.children.length, 0);
});
