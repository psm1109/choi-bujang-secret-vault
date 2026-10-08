import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { decide } from '../xdr/brute-force/decide.mjs';
import { extractAlerts } from '../xdr/brute-force/read-alerts.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
const ambiguous = fixture.alerts.find(alert => alert.id === 'bf-11');
const jevResponse = noul => ({ answers: { is_brute_force: { type: 'noul', noul } } });

test('격리 환경에서 import·process·파일·네트워크 없이 판단 모듈 실행', async () => {
  const source = await readFile(new URL('../xdr/brute-force/decide.mjs', import.meta.url), 'utf8');
  const child = spawnSync(process.execPath, ['--experimental-vm-modules', '--input-type=module', '-e', `
    import { readFileSync } from 'node:fs';
    import { createContext, SourceTextModule } from 'node:vm';
    const { source, alerts } = JSON.parse(readFileSync(0, 'utf8'));
    const context = createContext({ console: { error() {} } });
    const module = new SourceTextModule(source, { context });
    await module.link(() => { throw new Error('외부 import 금지'); });
    await module.evaluate();
    const counts = { block: 0, alert: 0, record: 0 };
    for (const alert of alerts) counts[(await module.namespace.decide(alert)).action]++;
    console.log(JSON.stringify({ exports: Object.keys(module.namespace), counts }));
  `], { input: JSON.stringify({ source, alerts: fixture.alerts }), encoding: 'utf8', timeout: 10000 });
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), {
    exports: ['decide'], counts: { block: 10, alert: 9, record: 9 },
  });
});

test('무차별 대입 판단 모듈', async t => {
  const originalFetch = globalThis.fetch;
  const originalUrl = process.env.JEV_API_URL;
  const originalKey = process.env.JEV_API_KEY;
  const originalError = console.error;
  const diagnostics = [];
  console.error = line => diagnostics.push(line);
  process.env.JEV_API_URL = 'https://jev.invalid/confidence';
  process.env.JEV_API_KEY = 'test-only-placeholder';
  t.after(() => {
    globalThis.fetch = originalFetch;
    console.error = originalError;
    for (const [name, value] of [['JEV_API_URL', originalUrl], ['JEV_API_KEY', originalKey]]) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  await t.test('가상 경보의 공격·애매함·정상 분류와 추출 경보 호환', async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return Response.json(jevResponse(0.65));
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

  await t.test('실패 신호 없는 미확정 사건은 Jev 확신도의 임계값 적용', async () => {
    for (const [confidence, action] of [[0, 'record'], [0.4999, 'record'], [0.5, 'alert'],
      [0.8499, 'alert'], [0.85, 'block'], [1, 'block']]) {
      globalThis.fetch = async () => Response.json(jevResponse(confidence));
      assert.deepEqual(await decide({ description: '판단에 필요한 사건 정보 부족' }), {
        action, confidence, reason: '판단 근거 부족',
      });
    }
  });

  await t.test('애매한 실패 경보는 낮은 Jev 공격 확률에도 알림 유지', async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return Response.json(jevResponse(0.23));
    };
    for (const alert of fixture.alerts.slice(10, 19)) {
      const result = await decide(alert);
      assert.equal(result.action, 'alert');
      assert.equal(result.confidence, 0.5);
    }
    assert.equal(calls, 9);
    for (const confidence of [0, 0.4999, 0.5, 0.8499, 0.85, 1]) {
      globalThis.fetch = async () => Response.json(jevResponse(confidence));
      const result = await decide(ambiguous);
      assert.equal(result.confidence, Math.max(0.5, confidence));
      assert.equal(result.action, confidence >= 0.85 ? 'block' : 'alert');
    }
  });

  await t.test('계정 목록의 명확한 동일 비밀번호 대입은 Jev 없이 차단', async () => {
    let calls = 0;
    globalThis.fetch = async (_url, options) => {
      calls += 1;
      assert.equal(options.body.includes('user01'), false);
      assert.equal(options.body.includes('user02'), false);
      return Response.json(jevResponse(0.2));
    };
    for (const accounts of [['user01', 'user02'], 'user01, user02']) {
      const result = await decide({
        rule: { description: '동일한 비밀번호로 로그인 실패가 반복됐습니다.' },
        data: { accounts },
      });
      assert.deepEqual(result, {
        action: 'block', confidence: 0.98, reason: '여러 계정에 같은 비밀번호 대입',
      });
    }
    assert.equal(calls, 0);
    // 같은 계정의 중복·빈 목록은 여러 계정 근거가 아닙니다.
    for (const accounts of [['user01', 'user01'], 'user01, user01', ['', ' '], [null, 2]]) {
      assert.equal((await decide({
        rule: { description: '동일한 비밀번호로 로그인 실패가 반복됐습니다.' }, data: { accounts },
      })).action, 'alert');
    }
    // 여러 계정만으로 동일 비밀번호 대입을 추정하거나 정상 성공을 차단하지 않습니다.
    assert.equal((await decide({
      rule: { description: '로그인 실패가 3건입니다.' }, data: { accounts: ['user01', 'user02'] },
    })).action, 'alert');
    assert.equal((await decide({
      rule: { description: '로그인이 성공했습니다.' }, data: { accounts: ['user01', 'user02'] },
    })).action, 'record');
  });

  await t.test('누락·오류·잘못된 응답은 alert', async () => {
    const responses = [
      async () => { throw new Error('모의 연결 오류'); },
      async () => new Response('', { status: 503 }),
      async () => new Response('invalid-json'),
      ...[{}, { confidence: 0.95 }, jevResponse('0.9'), jevResponse(-1), jevResponse(1.1),
        jevResponse(null), { answers: { is_brute_force: { type: 'choice', noul: 0.9 } } },
        { answers: { wrong_question: { type: 'noul', noul: 0.9 } } }]
        .map(body => async () => Response.json(body)),
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
    assert.ok(diagnostics.some(line => line.includes('http_error (HTTP 503)')));
    assert.ok(diagnostics.some(line => line.includes('response_invalid')));
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
      assert.deepEqual(Object.keys(body).sort(), ['model', 'questions', 'state']);
      assert.equal(body.model, 'jev-latest');
      assert.equal(body.state.moduleKey, 'brute-force');
      assert.equal(body.questions.is_brute_force.type, 'noul');
      assert.ok(body.questions.is_brute_force.instructions);
      assert.deepEqual(Object.keys(body.questions.is_brute_force.criteria).sort(), ['false', 'true']);
      for (const marker of [alert.data.srcip, alert.data.srcuser, alert.data.password,
        alert.id, alert.agent.name, '원문-전송-금지']) {
        assert.equal(options.body.includes(marker), false);
      }
      return Response.json({ ...jevResponse(0.7), reason: alert.data.password });
    };
    assert.equal((await decide(alert)).reason, '짧은 시간 같은 주소의 로그인 실패 연속');
  });

  await t.test('정보 부족·부정 표현과 다수 실패 뒤 성공은 정상으로 단정하지 않음', async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return Response.json(jevResponse(0.6));
    };
    for (const alert of [null, {}, { description: '여러 계정에 같은 비밀번호 대입이 아닙니다.' },
      { description: '로그인 실패 48건 뒤에 성공했습니다.', srcip: '192.0.2.10' }]) {
      assert.equal((await decide(alert)).action, 'alert');
    }
    assert.equal(calls, 4);
    for (const marker of ['test-only-placeholder', 'https://jev.invalid', 'synthetic-sensitive-marker']) {
      assert.equal(diagnostics.some(line => line.includes(marker)), false);
    }
  });
});
