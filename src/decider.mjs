// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계: 등록된 기기의 자료실 읽기만 허용하고 나머지는 기본 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered']);

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
