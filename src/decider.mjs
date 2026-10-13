// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 등록 기기의 자료실 읽기에 7단계 복합 가상 사건 추가 확인을 적용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'step_up_required']);

// 출처는 엔진 계약의 signals.source만 확인합니다. 클라이언트 헤더로 보완하지 않습니다.
// judge_fixture는 가상 사건이며 실제 위치 증거가 아닙니다. unknown은 정상값이 아닙니다.
function validConnectionInput(request) {
  const signals = request.signals;
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)) return false;
  if (!['none', 'judge_fixture'].includes(signals.source)) return false;
  // 계약에 없는 지역명 목록으로 정상·복합 사건을 같은 거부로 만들지 않습니다.
  if (typeof signals.region !== 'string' || signals.region.length === 0
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
    // 제공된 가상 사건 형식의 risk_signal을 사용하며 지역은 판단하지 않습니다.
    const riskEvents = request.recentEvents.filter(event => event.kind === 'risk_signal'
      && event.ageSeconds <= 60 && event.count >= 20);
    const unusualAccess = request.signals.source === 'judge_fixture'
      && Number.isInteger(request.signals.hour) && request.signals.hour < 6
      && request.signals.network === 'unusual'
      && riskEvents.length > 0;
    // 복합 가상 사건을 먼저 확인하고, 사건보다 오래되지 않은 검증된 가상 로그인만 허용합니다.
    // 실제 새 로그인 시각 검증·자료 차단 실측을 대신하는 조건은 아닙니다.
    const fixtureReconfirmed = unusualAccess && request.stepUp?.verified === true
      && Number.isInteger(request.stepUp.authAgeSeconds)
      && request.stepUp.authAgeSeconds >= 0 && request.stepUp.authAgeSeconds <= 900
      && riskEvents.every(event => request.stepUp.authAgeSeconds <= event.ageSeconds);
    if (unusualAccess && !fixtureReconfirmed) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'step_up',
        reasonCode: 'step_up_required',
        ruleIds: ['device_registered', 'step_up_required'],
      };
    }
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
