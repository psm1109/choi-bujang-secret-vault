// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 등록 기기의 자료실 읽기·수정에 구역 규칙과 7단계 추가 확인을 적용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'step_up_required',
  'notes_read', 'notes_update', 'instructor_notice_update']);

const UUID_PATH = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const EMPTY_QUERY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

// ID 외 단어·기능 이름·인코딩 경로는 단건 경로로 취급하지 않습니다.
function zoneRule(request) {
  if (typeof request.path !== 'string' || request.service !== 'notes' || request.queryLength !== 0
      || request.querySha256 !== EMPTY_QUERY_SHA256) return null;
  // 7단계부터 사용한 공개 가상 요청 경로를 정확히 보존합니다. 기능 경로로 확장하지 않습니다.
  if (request.method === 'GET' && request.route === 'GET /notes/:id'
      && request.path === '/notes/demo') return 'notes_read';
  for (const prefix of ['', '/api']) {
    if (new RegExp(`^${prefix}/notes/${UUID_PATH}$`, 'u').test(request.path)) {
      if (request.method === 'GET' && request.route === `GET ${prefix}/notes/:id`) return 'notes_read';
      if (request.method === 'PUT' && request.route === `PUT ${prefix}/notes/:id`) return 'notes_update';
    }
    if (request.method === 'PUT' && request.route === `PUT ${prefix}/instructor-notices/:id`
        && new RegExp(`^${prefix}/instructor-notices/${UUID_PATH}$`, 'u').test(request.path)) {
      return 'instructor_notice_update';
    }
  }
  return null;
}

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

  const rule = zoneRule(request);
  const verifiedContext = validConnectionInput(request)
    && typeof request.subjectId === 'string' && request.subjectId.trim().length > 0
    && typeof request.deviceId === 'string' && /^[0-9a-f]{16}$/u.test(request.deviceId);
  // 현재 계약에 검증된 강사 권한은 없습니다. 클라이언트의 role로 허용하지 않습니다.
  if (verifiedContext && rule === 'instructor_notice_update') {
    return {
      schema: 'aleph.decision.v1', requestId: request.requestId,
      decision: 'deny', reasonCode: 'starter_not_ready',
      ruleIds: ['instructor_notice_update'],
    };
  }
  // 본인 소유의 최종 확인은 기존 자료 API의 검증된 userId와 owner_id로 수행합니다.
  if (verifiedContext && (rule === 'notes_read' || rule === 'notes_update')) {
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
      ruleIds: ['device_registered', rule],
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
