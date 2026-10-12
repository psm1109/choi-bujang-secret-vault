const PATTERNS = [
  {
    name: '서명 없는 새 서비스 등록',
    condition: '경보에 새 서비스 등록 또는 기존 서비스 실행 파일 변경과 서명 없음이 명시됐는지 찾는다. 임시 폴더 실행 파일, 평소 목록에 없는 서비스, 반복 등록 여부가 명시된 경우 함께 살핀다. 서명 미확인은 서명 없음으로 추정하지 않고, 설명만 변경되거나 기존 서명된 서비스가 실행되는 경우는 이 조건에서 제외한다. 서비스 등록이나 서명 없음 하나만으로 공격을 확정하지 않는다.',
    evidence: 'MITRE ATT&CK T1543은 서비스 등 시스템 프로세스를 생성·변경해 지속 실행을 확보하는 형태를 설명하며, 로컬 가상 경보 ps-01·ps-04·ps-06은 서명 없는 서비스 등록·변경 신호를 명시한다: https://attack.mitre.org/techniques/T1543/',
  },
  {
    name: '낯선 예약 작업 등록',
    condition: '경보에 처음 보는 예약 작업 생성 또는 임의 문자열의 작업 이름이 명시됐는지 찾고, 임시 폴더 실행 파일이나 수업 시간 밖 실행이 명시된 경우 함께 살핀다. 작업 이름의 모양만으로 악성을 추정하지 않는다. 기존 작업의 정상 실행·평소 업데이트 예약은 제외하며, 수업 중 작업 생성이나 서명 미확인만으로 공격을 확정하지 않는다.',
    evidence: 'MITRE ATT&CK T1053은 예약 작업 기능으로 악성 코드를 최초 또는 반복 실행하는 형태를 설명하며, 로컬 가상 경보 ps-02·ps-05는 낯선 작업과 임시 폴더 실행 파일을 명시한다: https://attack.mitre.org/techniques/T1053/',
  },
  {
    name: '시작 폴더의 낯선 프로그램 추가',
    condition: '경보에 시작 폴더로 프로그램이 추가됐거나 시작 프로그램이 변경됐다는 설명이 명시됐는지 찾는다. 평소 목록에 없는 프로그램 또는 예약 작업과 같은 임시 파일을 가리키는 경우 함께 살핀다. 시작 프로그램 목록을 읽기만 한 경우는 제외하며, 변경 1건·실행 기록 없음·서명 미확인만으로 공격을 확정하지 않는다.',
    evidence: '로컬 가상 경보 ps-03·ps-07은 시작 폴더의 낯선 프로그램 추가와 시작 프로그램·예약 작업의 공통 임시 파일을 명시하며, 시작 폴더를 통한 자동 실행의 직접 분류 근거는 T1543·T1053이 아닌 MITRE ATT&CK T1547.001이다: https://attack.mitre.org/techniques/T1547/001/',
  },
];

const text = value => typeof value === 'string' ? value.slice(0, 8192) : '';

function result(confidence, names) {
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    // 고정된 이름만 반환하며 경보 원문·계정·비밀값은 복사하지 않습니다.
    reason: names.length ? names.join(' · ') : '일치 패턴 없음',
  };
}

export function decide(alert) {
  const description = text(alert?.rule?.description ?? alert?.description);
  const path = text(alert?.data?.path ?? alert?.path);
  const scores = [0, 0, 0];
  const temporary = /임시 (?:폴더|파일)/u.test(description)
    || /(?:^|[\\/])Temp[\\/]/iu.test(path);
  const uncertain = /의심|추정|가능성|확인되지|미확인|아직 모|아직 모르/u.test(description);
  const unsigned = /서명 없는|서명이 없|서명 없음/u.test(description)
    && !/서명 없는.*(?:아니|없습니다)|서명이 없.*(?:아니|않)/u.test(description);
  const unfamiliar = /처음 보는|평소 목록에 없는|낯선/u.test(description)
    && !/평소 목록에 없는.*(?:아니|않)/u.test(description);

  const service = /서비스/u.test(description);
  const noService = /서비스 등록[은이가]?\s*없|서비스.*등록하지/u.test(description);
  const serviceChange = service && !noService && (
    /(?:새|신규) 서비스|서비스.*등록/u.test(description)
    || /서비스 실행 파일.*(?:바뀌|변경)/u.test(description));
  const repeatedService = /서비스 등록.*(?:연속|반복)/u.test(description);
  if (serviceChange) {
    scores[0] = unsigned ? 0.9 : 0.6;
    if ((unsigned && (temporary || unfamiliar || repeatedService))
        || (unfamiliar && temporary)) scores[0] = 0.95;
  } else if (service && !/기존.*서명된.*실행/u.test(description)) {
    // 설명 변경·같은 파일 재시작·등록 없는 임시 파일은 약한 근거입니다.
    scores[0] = 0.5;
  }

  const task = /예약 작업/u.test(description);
  const noTask = /예약 작업[은이가]?\s*없|예약 작업.*(?:만들지|생성하지|등록하지)/u.test(description);
  const normalTask = /기존 예약 작업.*(?:마쳤|완료)|업데이트 예약.*평소.*그대로/u.test(description);
  const randomTask = /작업 이름.*임의 문자열/u.test(description);
  const outsideClass = /수업 시간 밖/u.test(description)
    && !/수업 시간 밖.*(?:아니|않)/u.test(description);
  if (task && !noTask && !normalTask) {
    scores[1] = 0.55;
    if (unfamiliar || randomTask) scores[1] = 0.65;
    if ((unfamiliar || randomTask) && (temporary || outsideClass)) scores[1] = 0.95;
  }

  const startup = /시작 (?:폴더|프로그램|항목)/u.test(description);
  const readOnly = /읽기만|조회만/u.test(description);
  const noStartup = /시작 (?:폴더|프로그램|항목).*(?:변경|추가)[은이가]?\s*없|시작 (?:폴더|프로그램|항목).*(?:추가하지|변경하지)/u.test(description);
  const startupChange = /추가|변경|가리/u.test(description);
  const sharedTemporary = task && temporary && /같은.*함께 가리/u.test(description);
  const notExecuted = /실행.*(?:기록[은이가]?\s*없|않|아니)/u.test(description);
  if (startup && !readOnly && !noStartup) {
    scores[2] = 0.55;
    if (startupChange && (unfamiliar || sharedTemporary) && !notExecuted) scores[2] = 0.95;
  }

  // 근거가 추정·미확인 상태이면 높은 규칙 수준도 차단으로 올리지 않습니다.
  if (uncertain) {
    for (let i = 0; i < scores.length; i += 1) scores[i] = Math.min(scores[i], 0.65);
  }
  const confidence = Math.max(...scores);
  const names = PATTERNS.filter((_, index) => scores[index] >= 0.5).map(pattern => pattern.name);
  return result(confidence || 0.1, names);
}
