import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { SourceTextModule, createContext } from 'node:vm';
import { decide } from '../xdr/web-injection/decide.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/web-injection.json', import.meta.url), 'utf8'));
const event = (url, description = '', count = '1') => ({ data: { url, count }, rule: { description } });

test('가상 경보를 패턴 근거에 따라 분류하고 원본을 보존합니다', () => {
  const original = JSON.stringify(fixture);
  const blocked = new Set(['wi-01', 'wi-02', 'wi-03', 'wi-04', 'wi-05', 'wi-07', 'wi-08']);
  const reviewed = new Set(['wi-06', 'wi-09', 'wi-15', 'wi-16', 'wi-17']);
  for (const alert of fixture.alerts) {
    const out = decide(alert);
    assert.deepEqual(Object.keys(out).sort(), ['action', 'confidence', 'reason']);
    assert.equal(out.action, blocked.has(alert.id) ? 'block' : reviewed.has(alert.id) ? 'alert' : 'record', alert.id);
    assert.ok(out.confidence >= 0 && out.confidence <= 1);
    if (out.action === 'block') assert.ok(out.confidence >= 0.85);
    if (out.action === 'alert') assert.ok(out.confidence >= 0.5);
    assert.ok(out.reason && !/[\r\n]/u.test(out.reason));
  }
  assert.equal(JSON.stringify(fixture), original);
});

test('추출된 설명과 실제 인자·인코딩을 판정하며 이름이나 등급으로 차단하지 않습니다', () => {
  for (const alert of [
    event('/?q=1%27%20OR%201%3D1'),
    event('/?q=UNION+SELECT+title+FROM+notes'),
    event('/?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E'),
    event('/?path=..%2F..%2Fnotes'),
    { description: '스크립트 삽입 표기가 9번 반복됐습니다.' },
  ]) assert.equal(decide(alert).action, 'block');
  for (const alert of [
    event('/?q=%3Cscript%3E'), event('/?path=../notes'),
    event('/?q=UNION+SELECT'), event('/?q=%27'),
    event('/?q=x', 'SQL 구문 표기가 1번 있습니다.'),
    event('/?q=x', 'SQL 구문 주입이 의심됩니다.', '20'),
    event('/?q=%E0%A4%A', '주입처럼 보이는 표기가 있습니다.'),
  ]) assert.equal(decide(alert).action, 'alert');
  for (const alert of [
    null, {}, event('/?q=select-course'), event('/?q=script-class'),
    event('/?path=up-notes'), event('/script?select=x'),
    event('/?q=x', '스크립트 삽입 표식은 아닙니다.', '20'),
    event('/?q=x', 'SQL 구문은 없습니다.', '20'),
    { rule: { level: 15, mitre: ['T1190'] }, data: { count: '100' } },
  ]) assert.equal(decide(alert).action, 'record');
});

test('같은 폴더 mjs만 허용하는 격리 환경에서 키·네트워크 없이 2초 안에 판정합니다', async () => {
  const context = createContext({});
  const base = new URL('../xdr/web-injection/', import.meta.url);
  const patterns = new SourceTextModule(await readFile(new URL('patterns.mjs', base), 'utf8'), { context });
  const module = new SourceTextModule(await readFile(new URL('decide.mjs', base), 'utf8'), { context });
  await module.link(specifier => {
    assert.equal(specifier, './patterns.mjs');
    return patterns;
  });
  await module.evaluate({ timeout: 2000 });
  for (const alert of fixture.alerts) {
    context.input = alert;
    context.expected = decide(alert).action;
    context.decide = module.namespace.decide;
    const check = new SourceTextModule('if (decide(input).action !== expected) throw new Error("판정 불일치");', { context });
    await check.link(() => { throw new Error('추가 import 금지'); });
    await check.evaluate({ timeout: 2000 });
  }
});
