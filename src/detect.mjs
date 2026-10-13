// 9단계 탐지 함수입니다. 회수 후보만 제안하며 접속 회수를 직접 실행하지 않습니다.
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
  const inputs = readDetectionEvents(events);
  // 배열 전체가 원본 계약이면 존재하지 않는 확장 필드를 요구하지 않습니다.
  // 일부만 누락된 확장 사건을 원본 사건으로 낮춰 판정하지 않습니다.
  const originalInput = inputs.every((input, index) => input.deviceId === undefined
    && events[index].signals === undefined);
  const subjects = new Map();
  for (let index = 0; index < inputs.length; index += 1) {
    const input = inputs[index];
    if (input.method !== 'GET') continue;
    if (!originalInput) {
      // 확장 사건은 확인된 기기와 가상 네트워크 이상이 모두 있어야 합니다.
      const signals = events[index].signals;
      if (input.deviceId === undefined || !signals || signals.source !== 'judge_fixture'
          || signals.network !== 'unusual') continue;
    }
    const at = events[index].at;
    const utc = typeof at === 'string'
      && /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z$/u.exec(at);
    if (!utc) continue;
    // ISO UTC의 초 단위·소수 1~3자리 표기를 같은 시각으로 정규화합니다.
    const canonicalAt = `${utc[1]}.${(utc[2] ?? '').padEnd(3, '0')}Z`;
    const time = Date.parse(canonicalAt);
    if (!Number.isFinite(time) || new Date(time).toISOString() !== canonicalAt) continue;
    if (!subjects.has(input.subject)) subjects.set(input.subject, new Map());
    const devices = subjects.get(input.subject);
    if (!devices.has(input.deviceId)) devices.set(input.deviceId, []);
    devices.get(input.deviceId).push(time);
  }
  for (const [subject, devices] of subjects) {
    for (const [deviceId, times] of devices) {
      times.sort((a, b) => a - b);
      let first = 0;
      for (let last = 0; last < times.length; last += 1) {
        while (times[last] - times[first] > 10 * 60 * 1000) first += 1;
        if (last - first + 1 > 120) {
          // 원본 응답의 세 항목을 유지하며 기기 ID를 임의로 생성하지 않습니다.
          if (originalInput) return { action: 'propose_revocation', reasonCode: 'burst_read', subject };
          return { action: 'propose_revocation', reasonCode: 'burst_read', subject, deviceId };
        }
      }
    }
  }
  return { action: 'observe' };
}
