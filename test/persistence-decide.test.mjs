import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createContext, SourceTextModule, runInNewContext } from 'node:vm';
import { decide } from '../xdr/persistence/decide.mjs';

const base = new URL('../xdr/persistence/', import.meta.url);
const source = await readFile(new URL('decide.mjs', base), 'utf8');
const fixture = JSON.parse(await readFile(new URL('../fixtures/persistence.json', base), 'utf8'));
const patterns = JSON.parse(await readFile(new URL('patterns.json', base), 'utf8')).patterns;
const event = (description, path) => ({ rule: { description }, data: { path } });

test('패턴 상수를 원본 패턴 문서와 동일하게 보존합니다', () => {
  const constants = source.slice(0, source.indexOf('const text ='));
  const embedded = runInNewContext(`${constants}\nJSON.stringify(PATTERNS)`, {}, { timeout: 2000 });
  assert.deepEqual(JSON.parse(embedded), patterns);
});

test('가상 경보 24개를 분류하고 원본과 반환 계약을 보존합니다', () => {
  const original = JSON.stringify(fixture);
  const counts = { block: 0, alert: 0, record: 0 };
  const blocks = new Set(['ps-01', 'ps-02', 'ps-03', 'ps-04', 'ps-05', 'ps-06', 'ps-07', 'ps-08']);
  const alerts = new Set(['ps-09', 'ps-10', 'ps-11', 'ps-12', 'ps-13', 'ps-14', 'ps-15', 'ps-16']);
  for (const input of fixture.alerts) {
    const output = decide(input);
    assert.equal(output.action, blocks.has(input.id) ? 'block' : alerts.has(input.id) ? 'alert' : 'record', input.id);
    assert.deepEqual(Object.keys(output).sort(), ['action', 'confidence', 'reason']);
    assert.ok(Number.isFinite(output.confidence) && output.confidence >= 0 && output.confidence <= 1);
    assert.equal(output.action, output.confidence >= 0.85 ? 'block' : output.confidence >= 0.5 ? 'alert' : 'record');
    assert.ok(output.reason && !/[\r\n]/u.test(output.reason));
    for (const name of output.reason.split(' · ')) assert.ok(name === '일치 패턴 없음' || patterns.some(pattern => pattern.name === name));
    assert.deepEqual(decide({ rule: { description: input.rule.description }, data: { path: input.data.path } }), output);
    counts[output.action] += 1;
  }
  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
  assert.equal(JSON.stringify(fixture), original);
});

test('강한 신호의 조합과 미확인·부정·정상 신호를 구별합니다', () => {
  for (const input of [
    event('새 서비스 등록, 서명 없음'),
    event('낯선 예약 작업이 수업 시간 밖에 실행됩니다.'),
    event('시작 폴더에 평소 목록에 없는 프로그램이 추가됐습니다.'),
  ]) assert.equal(decide(input).action, 'block');
  for (const input of [
    event('새 서비스 등록'),
    event('새 서비스 등록, 서명은 미확인입니다.', 'C:\\Temp\\demo.exe'),
    event('낯선 예약 작업'),
    event('시작 폴더 변경 1건, 실행 기록은 없습니다.'),
    event('서명 없는 새 서비스 등록이 의심됩니다.', 'C:\\Temp\\demo.exe'),
    event('평소 목록에 없는 서비스 등록이 아니며 서명은 확인되지 않았습니다.'),
  ]) assert.equal(decide(input).action, 'alert');
  for (const input of [
    null, {}, event('로그인했습니다.'),
    event('시작 프로그램 목록을 읽기만 했습니다.'),
    event('기존 수업 도구 서비스가 서명된 채로 실행 중입니다.'),
    event('예약 작업은 없습니다.'),
    event('시작 폴더 변경은 없습니다.'),
    { rule: { level: 15, mitre: ['T1543', 'T1053'] }, data: { path: 'C:\\Temp\\demo.exe', count: '100' } },
  ]) assert.equal(decide(input).action, 'record');
});

test('외부 기능 없는 격리 환경에서 단일 파일만으로 즉시 답합니다', async () => {
  assert.ok(!/\bimport\b/u.test(source));
  const context = createContext({});
  const module = new SourceTextModule(source, { context });
  await module.link(() => { throw new Error('외부 모듈 접근 금지'); });
  await module.evaluate({ timeout: 2000 });
  assert.deepEqual(Object.keys(module.namespace), ['decide']);
  for (const input of fixture.alerts) {
    context.input = input;
    context.decide = module.namespace.decide;
    const output = runInNewContext('JSON.stringify(decide(input))', context, { timeout: 2000 });
    assert.deepEqual(JSON.parse(output), decide(input));
  }
});
