const PATTERNS = [
  {
    "name": "처음 보는 목적지로 대용량 전송",
    "condition": "경보 설명에 처음 보는 목적지와 대용량 또는 자료 묶음의 실제 반출이 함께 명시됐는지 찾고, bytes·files·count의 전송량·파일 수·반복 횟수를 함께 살핀다. 명령 통로를 통한 반복 전송이 명시되면 T1041 관련 신호로 본다. 목적지 주소만으로 처음 보는 곳이라고 추정하거나 임의의 대용량 기준을 만들지 않는다. 작은 파일·실패한 전송·정상 자료 주소의 단발 증가만으로 공격을 확정하지 않으며, 포트나 MITRE 번호만으로 사용 프로토콜을 확정하지 않는다.",
    "evidence": "가상 경보 ex-01·ex-05·ex-09는 낯선 목적지로 자료 묶음 또는 명령 통로의 큰 파일 반복 전송을 명시하며, MITRE T1041은 기존 명령 통로의 유출, T1048은 그 통로와 다른 프로토콜의 유출을 설명하므로 프로토콜 근거가 없는 경보의 기법은 확정하지 않는다: https://attack.mitre.org/techniques/T1041/ ; https://attack.mitre.org/techniques/T1048/"
  },
  {
    "name": "업무 시간 밖 압축 파일 반출",
    "condition": "경보 설명에 업무·수업 시간 밖이라는 정황과 압축 파일의 실제 외부 전송이 함께 명시됐는지 찾고, 처음 보는 목적지와 전송량을 함께 살핀다. 신뢰할 일정·시간대가 없으면 timestamp만으로 업무 시간 밖이라고 추정하지 않는다. 압축 파일 생성만 있고 외부 전송이 없는 경우는 반출에서 제외하며, 승인된 백업이나 시간 밖이라는 신호 하나만으로 공격을 확정하지 않는다.",
    "evidence": "가상 경보 ex-02는 수업 시간 밖 압축 파일의 낯선 주소 반출을 명시하며, MITRE T1048의 탐지 설명은 시간 밖 활동·비정상적으로 큰 전송량을 신호로 제시하지만 압축·시간만으로 다른 프로토콜 사용을 입증하지는 않는다: https://attack.mitre.org/techniques/T1048/"
  }
];

const text = value => typeof value === 'string' ? value.slice(0, 8192) : '';
const number = value => {
  if (typeof value !== 'number' && typeof value !== 'string') return null;
  if (typeof value === 'string' && !/^\d+(?:\.\d+)?$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
};

export function decide(alert) {
  const description = text(alert?.rule?.description ?? alert?.description);
  const data = alert?.data;
  const bytes = number(data?.bytes);
  const count = number(data?.count);
  const files = number(data?.files);
  const scores = [0, 0];
  // 주소·시각·규칙 수준만으로 낯선 목적지·업무 시간·공격을 추정하지 않습니다.
  const unfamiliar = /처음 보는|처음 봅니다|평소와 다른 주소|다른 주소|낯선/u.test(description)
    && !/(?:처음 보는|낯선).*(?:아니|않)/u.test(description);
  const outsideHours = /(?:업무|수업) 시간 밖/u.test(description)
    && !/(?:업무|수업) 시간 밖.*(?:아니|않)/u.test(description);
  const archive = /압축 파일/u.test(description);
  const bulk = /대용량|큰 파일|자료실 전체|자료\s*\d+건|메모 묶음/u.test(description)
    && !/큰 파일[은이가]?\s*(?:아니|없)/u.test(description);
  const repeated = /반복|연속|(?:전송이|전송)\s*(?:[2-9]\d*|1\d+)번/u.test(description)
    || (count !== null && count > 1);
  const commandChannel = /명령 통로/u.test(description);
  const unusualPort = /평소에 쓰지 않던 포트/u.test(description);
  const sent = /나갔|올라갔|복사됐|전송됐|전송이|전송은|연속 전송/u.test(description);
  const incomplete = /실패|취소|외부 전송.*(?:없|않)|전송.*(?:없|않|미확인)|반출.*(?:없|않)/u.test(description)
    || bytes === 0;
  const uncertain = /의심|추정|가능성|미확인|확인되지|처럼 보이는|일부만/u.test(description);
  const approved = /(?:승인된|허용된|정기) 백업|승인된 전송/u.test(description);
  const normal = /내 메모.*(?:읽었|저장)|공지를 읽었|작은 동기화가 끝났|검색 결과 한 페이지|화면 새로고침|첨부 그림 한 장|세션 확인|로그아웃/u.test(description);

  // 전송량의 임의 기준 대신 설명에 명시된 규모와 반복 근거를 사용합니다.
  const related = unfamiliar || bulk || repeated || commandChannel || unusualPort
    || /전송량|파일 수.*늘|백업처럼/u.test(description);
  if (related) scores[0] = 0.55;
  if (archive || outsideHours) scores[1] = 0.55;
  if (sent && !incomplete) {
    if (unusualPort && repeated && bytes !== null && bytes > 0) scores[0] = 0.9;
    if (bulk && (unfamiliar || repeated || unusualPort || /자료실 전체/u.test(description))) scores[0] = 0.95;
    if (archive && unfamiliar && (repeated || (files !== null && files > 1))) scores[0] = 0.9;
    if (outsideHours && repeated) scores[0] = Math.max(scores[0], 0.9);
    if (archive && outsideHours && unfamiliar) scores[1] = 0.95;
  }
  // 성공하지 않은 전송과 불확실한 근거는 차단하지 않습니다.
  if (incomplete || uncertain) {
    for (let i = 0; i < scores.length; i += 1) scores[i] = Math.min(scores[i], 0.65);
  }
  if (approved || (normal && !unfamiliar && !outsideHours && !bulk && !repeated && !unusualPort && !commandChannel)) {
    scores.fill(0);
  }
  const confidence = Math.max(0.1, ...scores);
  const names = PATTERNS.filter((_, index) => scores[index] >= 0.5).map(pattern => pattern.name);
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    // 고정된 패턴 이름만 반환하며 경보 원문과 비밀값은 복사하지 않습니다.
    reason: names.length ? names.join(' · ') : '일치 패턴 없음',
  };
}
