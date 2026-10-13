const PATTERNS = [
  {
    "name": "관리자 그룹 추가·해제 직후 재가입",
    "condition": "관리자 그룹 추가·재가입이 명시됐는지 찾고, 원격 주소의 추가, 일반 계정의 추가 직후 권한 명령 실행, 같은 주소의 여러 계정 추가, 관리자 그룹에서 빠진 뒤 1분 만에 다시 관리자로 들어온 정황을 함께 살핀다. 해제 직후 재가입은 단순 추가와 구별되는 복합 근거다. 과제 그룹 추가·관리자가 아닌 그룹 변경·목록 조회는 제외한다. 단순 추가만으로 취약점 악용이나 계정 도용을 확정하지 않는다.",
    "evidence": "가상 경보 pv-01·pv-04·pv-05·pv-09가 원격 추가·추가 후 명령·여러 계정 추가·해제 직후 재가입을 명시하며, MITRE ATT&CK T1068은 취약점 악용을 통한 권한 상승의 분류 근거이지만 이 경보만으로 취약점 악용을 입증하지는 않는다: https://attack.mitre.org/techniques/T1068/"
  },
  {
    "name": "평소와 다른 관리자 명령·권한 사용",
    "condition": "관리자·권한 명령 실행에 처음 보는 출발 주소, 방금 얻은 관리자 권한 또는 다른 계정의 권한 사용이 동반되는지 찾고, 세션이 관리자 권한으로 바뀐 직후 처음 보는 주소에서 사용되는 정황도 살핀다. 구체적인 명령 이름이나 검증된 평소 명령 목록이 없으면 처음 보는 명령이라고 추정하지 않는다. 평소 주소의 단발 명령·실패 1건·취소된 권한 상승 창만으로 공격을 확정하지 않는다.",
    "evidence": "가상 경보 pv-02·pv-03·pv-04·pv-06·pv-08은 새 권한·낯선 주소·다른 계정 권한의 사용을 명시하며, MITRE ATT&CK T1078은 기존 계정의 자격 증명을 악용해 권한과 접근을 확보하는 형태를 설명하지만 낯선 명령 자체는 도용의 증거가 아니다: https://attack.mitre.org/techniques/T1078/"
  },
  {
    "name": "업무 시간 밖 권한 사용",
    "condition": "경보 설명에 수업·업무 시간 밖 관리자 권한 사용이 명시됐는지 찾고, 처음 보는 주소의 관리자 명령이나 관리자 그룹 추가와 명령 실행의 동반 여부를 살핀다. 신뢰할 업무 일정·시간대가 없으면 timestamp만으로 시간 밖 사용을 추정하지 않는다. 시간 밖이라는 신호 하나만으로 도용·취약점 악용을 확정하지 않는다.",
    "evidence": "가상 경보 pv-03·pv-07이 시간 밖의 낯선 주소 명령·그룹 추가와 명령 동반을 명시하므로 보조 신호로 삼으며, MITRE ATT&CK T1078은 계정 악용의 분류 근거일 뿐 업무 시간이나 시간 밖 사용의 악성을 정하지는 않는다: https://attack.mitre.org/techniques/T1078/"
  }
];

const text = value => typeof value === 'string' ? value.slice(0, 8192) : '';

export function decide(alert) {
  const description = text(alert?.rule?.description ?? alert?.description);
  const scores = [0, 0, 0];
  // 시각·계정·규칙 수준만으로 업무 일정이나 악성을 추정하지 않습니다.
  const uncertain = /의심|추정|가능성|미확인|확인되지/u.test(description);
  const incomplete = /취소|실패|명령[은이가]?\s*없|실행하지|실행.*않/u.test(description);
  const noGroupChange = /관리자 그룹[은이가]?\s*아니|관리자 그룹.*(?:추가하지|들어가지)|관리자 그룹 추가[은이가]?\s*없/u.test(description);
  const groupAdded = !noGroupChange && /관리자 그룹.*(?:추가|들어|가입)/u.test(description);
  const command = /(?:관리자|권한) 명령|관리자 그룹 추가와 명령 실행/u.test(description);
  const executed = command && !incomplete && /실행/u.test(description);
  const unfamiliar = /처음 보는|처음 봅니다|낯선/u.test(description)
    && !/처음 보는.*아니|낯선.*아니/u.test(description);
  const justElevated = /방금 관리자가|곧바로|관리자 권한으로 바뀌/u.test(description);
  const otherAccount = /다른 계정의 권한/u.test(description);
  const remote = /원격 주소/u.test(description);
  const multipleAccounts = /계정\s*(?:[2-9]\d*|1\d+)개/u.test(description);
  const rapidRejoin = /관리자 그룹에서 빠진.*(?:1분|60초).*다시 관리자로 (?:들어왔|들어갔)/u.test(description);
  const outsideHours = /(?:수업|업무) 시간 밖|업무처럼 보이지 않는 시각/u.test(description)
    && !/(?:수업|업무) 시간 밖.*아니/u.test(description);

  if (groupAdded) {
    scores[0] = 0.6;
    if (!incomplete && (remote || multipleAccounts || executed || rapidRejoin)) scores[0] = 0.95;
  }
  if (command || /권한 상승|관리자 권한으로 바뀌/u.test(description)) {
    scores[1] = 0.55;
    if (executed && (unfamiliar || justElevated || otherAccount)) scores[1] = 0.95;
    if (!incomplete && /관리자 권한으로 바뀌/u.test(description) && unfamiliar) scores[1] = 0.9;
  }
  if (outsideHours && (command || groupAdded || /관리자 권한|권한 상승/u.test(description))) {
    scores[2] = 0.6;
    if (executed && (unfamiliar || groupAdded)) scores[2] = 0.95;
  }
  // 취소·실패·미확인 근거는 차단 후보로 올리지 않습니다.
  if (uncertain || incomplete) {
    for (let i = 0; i < scores.length; i += 1) scores[i] = Math.min(scores[i], 0.65);
  }
  const confidence = Math.max(0.1, ...scores);
  const names = PATTERNS.filter((_, index) => scores[index] >= 0.5).map(pattern => pattern.name);
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    // 고정된 이름만 반환하며 원문·계정·비밀값을 복사하지 않습니다.
    reason: names.length ? names.join(' · ') : '일치 패턴 없음',
  };
}
