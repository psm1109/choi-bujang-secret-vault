// 확인용 패턴 설명입니다. 탐지 실행이나 차단 기준을 구현하지 않습니다.
// T1190은 외부 공개 앱 악용의 근거이며, 신호만으로 악용 성공을 확정하지 않습니다.
export const PATTERNS = [
  {
    name: '요청 인자 안의 SQL 구문',
    condition: '요청 인자에 SQL 조회·조건 구문을 이어 붙인 형태가 있는지 찾는다. SQL 또는 select라는 수업명, 단독 키워드나 따옴표만으로 확정하지 않으며, 반복 요청이 명시된 경우 함께 살핀다.',
    evidence: 'MITRE ATT&CK T1190은 외부 공개 앱 악용 사례로 SQL 주입을 명시한다: https://attack.mitre.org/techniques/T1190/',
  },
  {
    name: '요청 인자 안의 스크립트 태그',
    condition: '요청 인자에 <script> 시작·종료 태그나 스크립트 삽입 표식이 명시되어 있는지 찾는다. 스크립트라는 수업 단어만으로 확정하지 않으며, 반복 요청이 명시된 경우 함께 살핀다.',
    evidence: 'MITRE ATT&CK T1190의 외부 공개 앱 악용 범위에서 검토할 후보 신호이며, 스크립트 삽입의 직접 근거는 OWASP XSS 설명이다; 태그만으로 T1190 성공을 확정하지 않는다: https://attack.mitre.org/techniques/T1190/ ; https://community.owasp.org/attacks/xss/',
  },
  {
    name: '요청 인자 안의 상위 경로 이동 반복',
    condition: '요청 인자의 경로 값에 ../가 반복되거나, 경보 설명에 여러 단계의 상위 경로 이동 또는 반복된 경로 이탈 시도가 명시되어 있는지 찾는다. up이라는 이름이나 반복 근거 없는 단일 표기만으로 확정하지 않는다.',
    evidence: 'MITRE ATT&CK T1190은 C0017 사례에서 외부 공개 앱의 디렉터리 탐색 취약점 악용을 설명한다; ../ 반복은 그 형태를 살피는 후보 신호다: https://attack.mitre.org/techniques/T1190/',
  },
];
