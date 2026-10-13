# 10단계 정책 차이 미리보기

기본 실행은 파일을 읽고 결과를 터미널에 표시합니다. `--confirm`을 지정하면 별도 로컬 시험 사본의 두 정책 파일만 복원합니다. 운영 API 호출·감사 기록 변경은 하지 않습니다.
실제 안전 사본은 현재 저장소에 제공되어 있지 않습니다. 현재 정책으로 사본을 새로 만들어 침해 전 검증 자료로 취급하지 마세요.

침해 전에 별도로 검증·보관한 JSON 사본, 그 **원본 바이트**의 Ed25519 분리 서명(64바이트 바이너리), 사본과 별도로 신뢰한 공개키 PEM이 필요합니다. 비밀키는 입력하지 않습니다.
서명자의 신뢰성과 검증 사실은 외부에서 확보해야 합니다. 서명은 내용과 시각의 서명자 진술을 검증하며 실제 침해 시점을 알아내지 않습니다.
`--before`에는 확인된 침해 시작 시각을 UTC ISO 형식으로 입력합니다.

사본 계약: `schema`는 `aleph.policy-backup.v1`, `version`은 영숫자·점·밑줄·하이픈 1~80자입니다.
`createdAt`, `verifiedAt`는 `2026-10-12T00:00:00.000Z` 형식이며 생성 ≤ 검증 < 침해 시작 ≤ 현재 시각이어야 합니다.
`files`는 정확히 `src/decider.mjs`, `src/detect.mjs` 두 키를 가지며 각각 `content`(UTF-8 정책 소스)와 `sha256`(내용의 소문자 SHA-256)을 포함합니다.
사본에 계정 정보·키·토큰·메모 본문을 넣지 마세요. 사본이나 공개키를 이 도구가 자동 생성하거나 신뢰하지 않습니다.

편집기의 **터미널**에서 경로와 침해 시각을 실제 검증 자료에 맞춰 실행합니다:

```powershell
npm.cmd run policy:preview -- --backup C:\safe\policy.json --signature C:\safe\policy.sig --trusted-key C:\trusted\policy-public.pem --before 2026-10-13T00:00:00.000Z --trial-root .
```

정상 결과는 `preview_only`, 복원 후보 `version`, 검증 시각, 사본·신뢰 공개키 지문, 비교 파일과 `changes`입니다.
변경 범위는 공통 앞·뒤 줄을 제외한 구간으로, 구간 사이의 동일한 줄도 포함할 수 있습니다. `start`는 1부터 시작하며 `lines: 0`은 삽입·삭제 경계입니다. 줄바꿈 변경도 범위에 반영합니다.
메모나 비밀값 노출을 피하려고 소스 본문 대신 파일별 현재·사본 해시와 줄 범위를 표시합니다. 변화가 없으면 `changes`는 빈 배열입니다.
사본 없음, 서명·내용 해시 불일치, 신뢰 공개키 불일치, 침해 이후 검증, 대상 파일 누락·추가는 모두 종료 코드 1로 중단하며 미리보기 일부도 출력하지 않습니다.
설정 단계와 운영 복원 경로는 변경하지 않습니다.

## 확인 후 시험 정책 복원

1. 운영 배포에 연결되지 않은 별도 로컬 시험 사본을 준비합니다. 그 루트에 `.aleph-policy-trial.json`을 아래 내용으로 작성합니다. 현재 자료실 루트에 직접 복원하는 것은 거부합니다. 시험 중 다른 프로세스가 시험 파일을 편집하지 않도록 하세요.

```json
{"schema":"aleph.policy-trial.v1","environment":"local-test"}
```

2. 위 미리보기 명령의 `--trial-root`를 시험 사본 경로로 바꾸어 실행합니다. `version`, `changes`, `currentHashes`와 `confirmation`을 확인합니다. 같은 인자로 실행 끝에 `--confirm <표시된 confirmation>`을 붙이면 확인한 변경을 적용합니다. 현재 정책·서명 사본·버전·침해 시각·신뢰키가 달라지면 확인값이 맞지 않아 중단합니다. 심볼릭 링크와 하드링크 대상도 거부합니다.
3. 쓰기 대상은 시험 사본의 `src/decider.mjs`, `src/detect.mjs` 중 변경된 파일뿐입니다. API 소유자 검사, 다른 서비스와 XDR 규칙, 설정, 자료 DB, 감사 이력은 복원 범위에 포함하지 않습니다. 따라서 정책 파일 외의 침해 변경을 복구하는 기능은 아닙니다.
4. 결과의 `trial_restored`는 파일 복원 결과이며 요청 시험 통과를 뜻하지 않습니다. 시험 사본의 **터미널**에서 아래 명령으로 정상·금지 가상 요청을 확인합니다.

```powershell
node --test --test-isolation=none test/decider-input.test.mjs test/decider-unusual-access.test.mjs test/decider-zones.test.mjs test/detect-input.test.mjs test/detect-compound.test.mjs test/auth-api.test.mjs test/notes-api.test.mjs
```

A의 등록 정상 단건 요청은 `allow`, A의 본인 자료 API 조회·수정은 정상이어야 합니다. B의 A 자료 GET·PUT·DELETE는 기존 API 소유자 검사에서 404여야 합니다. 판정 요청의 가명 주체 ID를 DB 소유자 ID와 임의로 비교하지 않습니다.
실제 계정 A/B 접속, 운영 엔진·심판 판정은 별도 확인이 필요합니다. 시험 실패 시 운영 적용을 진행하지 말고 첫 오류와 복원된 두 파일을 기준으로 다음 한 가지 조치를 정합니다.

각 파일은 임시 파일로 준비한 뒤 교체하고 일반 쓰기 오류가 발생하면 이미 교체한 파일을 원래 시험 내용으로 되돌립니다. 프로세스 강제 종료·전원 중단에 대한 다중 파일 원자성은 보장하지 않으므로 재시작 시 미리보기를 다시 확인하세요.
