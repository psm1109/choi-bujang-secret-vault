// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계: 등록된 기기의 자료실 읽기만 허용하고 나머지는 기본 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered']);

// 출처는 엔진 계약의 signals.source만 확인합니다. 클라이언트 헤더로 보완하지 않습니다.
// judge_fixture는 가상 사건이며 실제 위치 증거가 아닙니다. unknown은 정상값이 아닙니다.
function validConnectionInput(request) {
  const signals = request.signals;
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)) return false;
  if (!['none', 'judge_fixture'].includes(signals.source)) return false;
  if (!['local', 'foreign', 'unknown'].includes(signals.region)
      || !['usual', 'unusual', 'unknown'].includes(signals.network)) return false;
  if (signals.hour !== null
      && (!Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 23)) return false;
  if (signals.source === 'none'
      && (signals.region !== 'unknown' || signals.network !== 'unknown')) return false;
  if (!Array.isArray(request.recentEvents) || request.recentEvents.length > 12) return false;
  return Array.from(request.recentEvents).every(event => event && typeof event === 'object'
    && !Array.isArray(event) && typeof event.kind === 'string' && event.kind.length > 0
    && Number.isInteger(event.ageSeconds) && event.ageSeconds >= 0
    && Number.isInteger(event.count) && event.count >= 0);
}

export async function decide(request) {
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  const readingNotes = request.service === 'notes' && request.method === 'GET'
    && validConnectionInput(request)
    && typeof request.subjectId === 'string' && request.subjectId.length > 0
    && ((request.route === 'GET /notes' && request.path === '/notes')
      || (request.route === 'GET /notes/:id' && /^\/notes\/[^/?#]+$/u.test(request.path))
      || (request.route === 'GET /api/notes' && request.path === '/api/notes')
      || (request.route === 'GET /api/notes/:id' && /^\/api\/notes\/[^/?#]+$/u.test(request.path)));
  if (readingNotes) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: ['device_registered'],
    };
  }

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: [RULE_IDS[0]],
  };
}
