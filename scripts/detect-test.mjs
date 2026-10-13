import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const subject = 'learner_fixture';
const deviceId = 'aaaaaaaaaaaaaaaa';

function reads(count, { intervalSeconds = 2, owner = subject, start = START,
  network = 'usual', source = 'judge_fixture', device = deviceId } = {}) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * intervalSeconds * 1000).toISOString(),
    method: 'GET', identity: { sub: owner }, deviceId: device,
    signals: { source, network },
  }));
}

// 원본 계약의 사건을 그대로 시험합니다. 확장 필드가 없는 사건도 회수 제안을 낼 수 있어야 합니다.
function originalReads(count, options) {
  return reads(count, options).map(({ at, method, identity }) => ({ at, method, identity }));
}

const cases = [
  { name: '원본 계약·정상 조회 30건', events: originalReads(30), expected: { action: 'observe' } },
  { name: '원본 계약·10분 안에 120건', events: originalReads(120), expected: { action: 'observe' } },
  { name: '원본 계약·10분 안에 121건', events: originalReads(121), expected: {
    action: 'propose_revocation', reasonCode: 'burst_read', subject } },
  { name: '원본 계약·폭주 조회 200건', events: originalReads(200), expected: {
    action: 'propose_revocation', reasonCode: 'burst_read', subject } },
  { name: '원본 계약·서로 다른 사용자 각 100건', events: [...originalReads(100),
    ...originalReads(100, { owner: 'other_fixture' })].sort((a, b) => a.at.localeCompare(b.at)),
    expected: { action: 'observe' } },
  { name: '원본 계약·10분 밖으로 흩어진 조회 200건', events: originalReads(200,
    { intervalSeconds: 7 }), expected: { action: 'observe' } },
  { name: '정상 조회 30건', events: reads(30), expected: { action: 'observe' } },
  { name: '이상 네트워크·10분 안에 120건', events: reads(120, { network: 'unusual' }), expected: { action: 'observe' } },
  { name: '복합 의심·10분 안에 121건', events: reads(121, { network: 'unusual' }), expected: {
    action: 'propose_revocation', reasonCode: 'burst_read', subject, deviceId } },
  { name: '복합 의심·폭주 조회 200건', events: reads(200, { network: 'unusual' }), expected: {
    action: 'propose_revocation', reasonCode: 'burst_read', subject, deviceId } },
  { name: '서로 다른 사용자 각 100건', events: [...reads(100, { network: 'unusual' }),
    ...reads(100, { owner: 'other_fixture', network: 'unusual' })].sort((a, b) => a.at.localeCompare(b.at)),
  expected: { action: 'observe' } },
  { name: '10분 밖으로 흩어진 조회 200건', events: reads(200,
    { intervalSeconds: 7, network: 'unusual' }), expected: { action: 'observe' } },
  { name: '정상 네트워크·다량 조회', events: reads(200), expected: { action: 'observe' } },
  { name: '이상 네트워크·정상 조회량', events: reads(30, { network: 'unusual' }), expected: { action: 'observe' } },
  { name: '지역만 다른 다량 조회', events: reads(200).map(event => ({ ...event,
    signals: { ...event.signals, region: 'foreign' } })), expected: { action: 'observe' } },
  { name: '확장 사건·신호 누락·다량 조회', events: reads(200).map(({ signals, ...event }) => event),
    expected: { action: 'observe' } },
  { name: '클라이언트 출처·다량 조회', events: reads(200, { source: 'client', network: 'unusual' }),
    expected: { action: 'observe' } },
  { name: '대상 기기 누락·복합 의심', events: reads(200, { network: 'unusual' })
    .map(({ deviceId, ...event }) => event), expected: { action: 'observe' } },
  { name: '정상 기기와 함께 있어도 의심 기기 하나만 제안', events: [
    ...reads(200, { device: 'bbbbbbbbbbbbbbbb' }), ...reads(121, { network: 'unusual' }),
  ], expected: { action: 'propose_revocation', reasonCode: 'burst_read', subject, deviceId } },
];

// This is a practice contract, not a live engine assertion or judge score.
export async function checkDetection(detect) {
  if (typeof detect !== 'function') throw new TypeError('src/detect.mjs에서 detect 함수를 내보내야 합니다.');
  const results = [];
  for (const item of cases) {
    const actual = await detect(item.events);
    const passed = isDeepStrictEqual(actual, item.expected);
    results.push({ name: item.name, passed: Boolean(passed) });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { detect } = await import('../src/detect.mjs');
    const results = await checkDetection(detect);
    for (const item of results) process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name}\n`);
    process.stdout.write('가상 사건 연습이며 실제 접속 회수나 심판 통과 증거가 아닙니다.\n');
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`탐지 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
