// 9단계에서 학생이 채우는 탐지 함수입니다. 이 기본값은 어떤 접속도 회수하지 않습니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.
// 입력을 펼치거나 직렬화하지 않고 필요한 가명·분류 값만 새 객체로 옮깁니다.
// 기존 연습 사건에는 기기·판정이 없습니다. 제공된 경우에만 읽고 누락값은 만들지 않습니다.
export function readDetectionEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  return Array.from(events, event => {
    if (!event || typeof event !== 'object' || Array.isArray(event)) {
      throw new TypeError('invalid_detection_event');
    }
    const subject = event.identity?.sub;
    const method = event.method;
    const deviceId = event.deviceId;
    const decision = event.decision;
    if (typeof subject !== 'string' || subject.trim().length === 0
        || !['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(method)
        || (deviceId !== undefined && (typeof deviceId !== 'string'
          || !/^[0-9a-f]{16}$/u.test(deviceId)))
        || (decision !== undefined && !['allow', 'deny', 'step_up'].includes(decision))) {
      // 오류에도 사건 값이나 원문을 넣지 않습니다.
      throw new TypeError('invalid_detection_event');
    }
    const input = { subject, method };
    if (deviceId !== undefined) input.deviceId = deviceId;
    if (decision !== undefined) input.decision = decision;
    return input;
  });
}

export function detect(events) {
  readDetectionEvents(events);
  return { action: 'observe' };
}
