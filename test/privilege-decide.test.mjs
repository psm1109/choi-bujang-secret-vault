import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createContext, SourceTextModule, runInContext, runInNewContext } from 'node:vm';
import { decide } from '../xdr/privilege/decide.mjs';

const base = new URL('../xdr/privilege/', import.meta.url);
const source = await readFile(new URL('decide.mjs', base), 'utf8');
const fixture = JSON.parse(await readFile(new URL('../fixtures/privilege.json', base), 'utf8'));
const patterns = JSON.parse(await readFile(new URL('patterns.json', base), 'utf8')).patterns;
const event = description => ({ rule: { description } });

test('상단 패턴은 원본과 동일하고 외부 기능 없는 단일 파일로 실행', async () => {
  assert.ok(!/\bimport\b/u.test(source));
  const constants = source.slice(0, source.indexOf('const text ='));
  assert.deepEqual(JSON.parse(runInNewContext(`${constants}\nJSON.stringify(PATTERNS)`, {}, { timeout: 1000 })), patterns);
  const context = createContext({});
  const module = new SourceTextModule(source, { context });
  await module.link(() => { throw new Error('외부 모듈 접근 금지'); });
  await module.evaluate({ timeout: 1000 });
  assert.deepEqual(Object.keys(module.namespace), ['decide']);
  context.decide = module.namespace.decide;
  for (const input of fixture.alerts) {
    context.input = input;
    assert.deepEqual(JSON.parse(runInContext('JSON.stringify(decide(input))', context, { timeout: 1000 })), decide(input));
  }
});

test('가상 경보 분류·정상 오차단 없음·반환 계약·원본 보존', () => {
  const original = JSON.stringify(fixture);
  const blocks = new Set(['pv-01','pv-02','pv-03','pv-04','pv-05','pv-06','pv-07','pv-08','pv-09']);
  const alerts = new Set(['pv-10','pv-12','pv-14','pv-16']);
  const counts = { block: 0, alert: 0, record: 0 };
  for (const input of fixture.alerts) {
    const output = decide(input);
    assert.equal(output.action, blocks.has(input.id) ? 'block' : alerts.has(input.id) ? 'alert' : 'record', input.id);
    assert.deepEqual(Object.keys(output), ['action','confidence','reason']);
    assert.ok(Number.isFinite(output.confidence) && output.confidence >= 0 && output.confidence <= 1);
    assert.equal(output.action, output.confidence >= 0.85 ? 'block' : output.confidence >= 0.5 ? 'alert' : 'record');
    assert.ok(!/[\r\n]/u.test(output.reason));
    for (const name of output.reason.split(' · ')) assert.ok(name === '일치 패턴 없음' || patterns.some(pattern => pattern.name === name));
    assert.deepEqual(decide(event(input.rule.description)), output);
    counts[output.action]++;
  }
  assert.deepEqual(counts, { block: 9, alert: 4, record: 13 });
  assert.equal(JSON.stringify(fixture), original);
});

test('해제 직후 재가입과 단독·추정·취소·부정 근거를 구별', () => {
  const description = '관리자 그룹에서 빠진 계정이 1분 뒤에 다시 관리자로 들어왔습니다.';
  assert.equal(decide(event(description)).action, 'block');
  assert.equal(decide(event(description.replace('1분','60초'))).action, 'block');
  for (const text of [description + ' 상황은 추정입니다.', description + ' 변경은 취소됐습니다.',
    '관리자 그룹에 다시 가입했습니다.', '관리자 그룹에서 빠진 계정이 1분 뒤에 다시 관리자로 들어오지 않았습니다.',
    '평소 주소에서 관리자 명령이 한 번 실행됐습니다.', '업무 시간 밖 관리자 권한 사용']) {
    assert.notEqual(decide(event(text)).action, 'block');
  }
  for (const input of [null, {}, event('관리자 그룹은 아닙니다.'), event('그룹 목록을 읽기만 했습니다.'),
    { timestamp: '2026-09-27T03:00:00+09:00', rule: { level: 15, mitre: ['T1068','T1078'] } }]) {
    assert.equal(decide(input).action, 'record');
  }
});

test('판단 이유는 경보의 비밀값 의심 문구를 복사하지 않음', () => {
  const output = decide(event('다른 계정의 권한으로 관리자 명령을 실행했습니다. token=synthetic-only'));
  assert.equal(output.action, 'block');
  assert.equal(output.reason, patterns[1].name);
});
