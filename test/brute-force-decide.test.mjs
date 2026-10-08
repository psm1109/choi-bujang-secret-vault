import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { decide } from '../xdr/brute-force/decide.mjs';
import { extractAlerts } from '../xdr/brute-force/read-alerts.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
const ambiguous = fixture.alerts.find(alert => alert.id === 'bf-11');

test('무차별 대입 판단 모듈', async t => {
  const originalFetch = globalThis.fetch;
  const originalUrl = process.env.JEV_API_URL;
  const originalKey = process.env.JEV_API_KEY;
  process.env.JEV_API_URL = 'https://jev.invalid/confidence';
  process.env.JEV_API_KEY = 'test-only-placeholder';
  t.after(() => {
    globalThis.fetch = originalFetch;
    for (const [name, value] of [['JEV_API_URL', originalUrl], ['JEV_API_KEY', originalKey]]) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  await t.test('가상 경보의 공격·애매함·정상 분류와 추출 경보 호환', async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return Response.json({ confidence: 0.65 });
    };
    const before = JSON.stringify(fixture);
    const results = await Promise.all(fixture.alerts.map(decide));
    assert.deepEqual(results.map(result => result.action), [
      ...Array(10).fill('block'), ...Array(9).fill('alert'), ...Array(9).fill('record'),
    ]);
    assert.equal(calls, 9, '애매한 경보만 Jev에 질의');
    for (const result of results) {
      assert.deepEqual(Object.keys(result), ['action', 'confidence', 'reason']);
      assert.ok(result.confidence >= 0 && result.confidence <= 1);
      assert.ok(result.reason && !/[\r\n]/.test(result.reason));
    }
    const extracted = extractAlerts(fixture);
    const extractedResults = await Promise.all(extracted.map(decide));
    assert.deepEqual(extractedResults.map(result => result.action), results.map(result => result.action));
    assert.equal(JSON.stringify(fixture), before);
  });

  await t.test('Jev 확신도의 임계값을 그대로 적용', async () => {
    for (const [confidence, action] of [[0, 'record'], [0.4999, 'record'], [0.5, 'alert'],
      [0.8499, 'alert'], [0.85, 'block'], [1, 'block']]) {
      globalThis.fetch = async () => Response.json({ confidence });
      assert.deepEqual(await decide(ambiguous), {
        action, confidence, reason: '짧은 시간 같은 주소의 로그인 실패 연속',
      });
    }
  });

  await t.test('누락·오류·잘못된 응답은 alert', async () => {
    const responses = [
      async () => { throw new Error('모의 연결 오류'); },
      async () => new Response('', { status: 503 }),
      async () => new Response('invalid-json'),
      ...[{}, { confidence: '0.9' }, { confidence: -1 }, { confidence: 1.1 },
        { confidence: null }].map(body => async () => Response.json(body)),
    ];
    for (const response of responses) {
      globalThis.fetch = response;
      const result = await decide(ambiguous);
      assert.equal(result.action, 'alert');
      assert.equal(result.confidence, 0.5);
    }
    globalThis.fetch = async () => { assert.fail('설정 누락 시 요청하면 안 됨'); };
    delete process.env.JEV_API_URL;
    assert.equal((await decide(ambiguous)).action, 'alert');
    process.env.JEV_API_URL = 'https://jev.invalid/confidence';
  });

  await t.test('응답 지연 시 제한 시간 뒤 alert', async () => {
    let signal;
    globalThis.fetch = async (_url, options) => {
      signal = options.signal;
      return new Promise(() => {});
    };
    const result = await decide(ambiguous);
    assert.equal(result.action, 'alert');
    assert.equal(signal.aborted, true);
  });

  await t.test('본문·결과에 원문과 식별자·비밀 필드를 포함하지 않음', async () => {
    const alert = structuredClone(ambiguous);
    alert.data.password = 'synthetic-sensitive-marker';
    alert.rule.description += ' 원문-전송-금지';
    globalThis.fetch = async (_url, options) => {
      const body = JSON.parse(options.body);
      assert.equal(options.headers.Authorization, 'Bearer test-only-placeholder');
      assert.equal(body.moduleKey, 'brute-force');
      for (const marker of [alert.data.srcip, alert.data.srcuser, alert.data.password,
        alert.id, alert.agent.name, '원문-전송-금지']) {
        assert.equal(options.body.includes(marker), false);
      }
      return Response.json({ confidence: 0.7, reason: alert.data.password });
    };
    assert.equal((await decide(alert)).reason, '짧은 시간 같은 주소의 로그인 실패 연속');
  });

  await t.test('정보 부족·부정 표현과 다수 실패 뒤 성공은 정상으로 단정하지 않음', async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return Response.json({ confidence: 0.6 });
    };
    for (const alert of [null, {}, { description: '여러 계정에 같은 비밀번호 대입이 아닙니다.' },
      { description: '로그인 실패 48건 뒤에 성공했습니다.', srcip: '192.0.2.10' }]) {
      assert.equal((await decide(alert)).action, 'alert');
    }
    assert.equal(calls, 4);
  });
});
