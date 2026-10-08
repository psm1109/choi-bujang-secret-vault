# XDR 보너스 경보

이 폴더는 보너스 여섯 개의 연습 경보입니다. 경보는 수업용으로 만든 Wazuh 모양이며, 실제 로그가 아닙니다. 정답은 이 저장소에 없습니다.

## 경보 묶음

`xdr/fixtures/<moduleKey>.json` 을 읽습니다. `moduleKey` 는 아래 여섯 개입니다.

| moduleKey | 보는 것 |
|---|---|
| `brute-force` | 짧은 시간에 몰린 로그인 실패 |
| `web-injection` | 웹 요청에 섞인 주입 형태 |
| `known-cve` | 이미 공개된 취약점을 노린 요청 형태 |
| `persistence` | 다시 켜도 남도록 심긴 서비스·예약 작업 |
| `privilege` | 평범한 계정의 갑작스러운 권한 상승 |
| `exfiltration` | 처음 보는 곳으로 빠지는 큰 전송 |

한 파일에는 명확한 공격, 애매한 시도, 정상 이벤트가 함께 들어 있습니다. 주소는 문서용 대역만 쓰고, 계정은 `user01` 같은 가상 이름입니다. `known-cve` 의 원격 조회 구문은 문서용 표기입니다. 그 문자열을 다른 시스템에 넣거나 변형하지 않습니다.

## 학생이 만드는 파일

항목마다 `xdr/<moduleKey>/decide.mjs` 를 만듭니다. `decide(alert)` 를 내보냅니다. 비동기 함수여도 됩니다. 반환은 아래 세 값입니다.

- `action`: `block`, `alert`, `record` 중 하나
- `confidence`: 0 이상 1 이하 숫자
- `reason`: 짧은 이유

명확한 공격은 `block`, 애매한 시도는 `alert`, 정상 이벤트는 `record` 입니다. 경보 원본은 고치지 않습니다.

## 실행

저장소 루트에서 항목 키 하나를 넣습니다.

```
node scripts/xdr-run.mjs brute-force
```

`npm run xdr:run -- brute-force` 도 같은 명령입니다. 실행기는 해당 경보마다 `decide` 를 부르고, 결과를 `xdr/<moduleKey>/result.json` 에 씁니다. 형식은 `aleph.xdr.result.v1` 이고, `decisions` 에는 경보 id·행동·확신도·이유가, `counts` 에는 `block`·`alert`·`record` 건수가 있습니다.

반환 형식이 틀린 경보는 `record` 로 남고, 오류 한 줄이 출력됩니다. 실행기 자체는 네트워크를 쓰지 않습니다. 판정자는 격리된 환경에서 같은 명령을 다시 실행해 결과를 봅니다. 이미 커밋된 `result.json` 만으로 판정이 끝나지 않습니다.

## 무차별 로그인 경보와 ZTNA 연결

`scripts/xdr-run.mjs`는 무차별 로그인 판단 결과를 `xdr/ztna-bridge.mjs`에 전달합니다.
`alert` 알림과 `block` 후보 처리 결과는 `xdr/alerts.log`에 JSON 한 줄씩 추가합니다.
경보 원문, 주소, 사용자 이름, 인증 정보는 이 로그에 넣지 않습니다.

자동 거부에는 신뢰하는 서버가 경보 번호를 ZTNA의 검증된
`classId`, `projectId`, `subjectId`, `deviceId`로 연결해야 합니다.
서버는 `runXdr({ root, moduleKey: 'brute-force', resolveVerifiedTarget })`의
`resolveVerifiedTarget({ moduleKey, alertId })` 콜백으로 그 네 값을 반환합니다.
연결이 없거나 조회가 실패하면 후보는 `unmapped_candidate`로 기록되고 규칙은 생성되지 않습니다.
시험 경보의 `srcuser`나 `srcip`를 ZTNA ID로 바꾸지 않습니다.

`block`이고 확신도가 0.85 이상인 후보에 한해 `xdr/deny-rules.json`에 별도 규칙을 생성합니다.
규칙은 주체·기기·반·프로젝트 조합의 SHA-256 지문, 근거 경보 번호, 생성 시각,
10분 뒤 만료 시각을 담습니다. 같은 실행의 정상 `record` 경보와 같은 검증 대상이면
새 규칙을 넣지 않고 그 대상의 기존 XDR 규칙도 제거합니다.
활성 규칙을 다시 입력해도 만료 시각은 연장하지 않습니다.
만료된 규칙은 판정에 쓰지 않으며 다음 경보 처리 때 파일에서 정리합니다.
알림과 임시 규칙 파일은 Git에서 제외합니다.

ZTNA 호출 위치에서는 `createXdrDecider({ root, baseDecide, baseRuleIds,
reasonCode, allowedReasonCodes })`가 반환한 `decide`와 `RULE_IDS`를 사용합니다.
`baseDecide`와 `baseRuleIds`는 기존 판정기에서 가져오며,
`reasonCode`는 운영 등록부의 `allowedReasonCodes`에서 허용한 XDR 거부 코드여야 합니다.
코드에 가상 허용 목록을 만들어 운영 등록 대신 쓰면 안 됩니다.
래퍼는 활성 XDR 규칙과 정확히 일치할 때만 거부 응답을 반환하고,
그 밖에는 기존 판정 결과를 그대로 반환합니다. 기존 판정기가 모든 요청을 거부하면
래퍼도 정상 요청을 허용으로 바꾸지 않습니다.

현재 `src/decider.mjs`는 모든 요청을 거부하는 시작 틀입니다.
실제 판정기 호출 위치, 검증된 경보 연결, 운영 허용 거부 코드가 저장소에 없어
운영 연결은 아직 적용하지 않았습니다. CLI 실행은 연결 없는 후보·알림 기록까지 수행합니다.
`node --test test/xdr-ztna-bridge.test.mjs`는 가상 연결과 정상 요청을 허용하는
시험 판정기로 재전송·정상 통과·만료·중복·기존 거부 보존을 확인합니다.
실제 접속 차단이나 심판 판정의 증거는 아닙니다.
