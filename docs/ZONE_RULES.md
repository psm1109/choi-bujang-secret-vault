# 판정기의 자료 구역 규칙

판정기는 엔진이 확인한 `subjectId`, `deviceId`, `deviceRegistered`, `service`,
`method`, `route`, `path`를 사용합니다. 기존 기기 등록·입력 검사·복합 사건 추가 확인을
유지하며 읽기뿐 아니라 메모 수정에도 적용합니다. 응답 다섯 항목은 유지합니다.

| 구역 규칙 | 정확한 경로·동작 | 결과 |
| --- | --- | --- |
| `notes_read` | `GET /api/notes`, `GET /api/notes/<UUID>` | 확인된 주체·등록 기기의 정상 요청 허용 |
| `notes_update` | `PUT /api/notes/<UUID>` | 같은 조건으로 허용, 최종 API에서 본인 소유 검사 |
| `instructor_notice_update` | `PUT /api/instructor-notices/<UUID>` | 검증된 강사 권한이 계약에 없어 거부 |

기존 엔진 연습용 `/notes` 접두 경로도 같은 규칙으로 검사합니다. UUID 외 값,
export 같은 기능 이름, 인코딩·추가 깊이·끝 슬래시, 메서드와 route 불일치,
알 수 없는 경로는 거부합니다. 기능 경로를 `:id`와 같은 깊이에 만들지 않습니다.
자료 ID는 경로로 선택합니다. 원문 쿼리가 없는 v1 계약에서는 쿼리로 자료 ID와 기능
선택을 구별할 수 없어 `queryLength: 0`과 빈 쿼리 지문인 요청만 허용합니다.
기존 `scope=shared` 주소는 삭제하지 않지만 이 판정기를 통한 접근은 거부합니다.

가명 `subjectId`를 Supabase 사용자 ID나 소유자로 간주하지 않습니다. 계약에 메모
소유자·검증된 강사 역할이 없어 판정기만으로 본인 소유나 강사임을 확인할 수 없습니다.
기존 최종 메모 API의 검증된 로그인 ID와 owner_id 조건을 유지합니다. 공지 수정 경로는
명시적 거부 정책이며 새 공지 API나 운영 허용 경로를 등록한 것이 아닙니다.
기존 자원 ID 헤더·자료·주소·메뉴·설정은 보존합니다.

편집기 **터미널**에서 다음 로컬 가상 시험을 실행합니다.

`node --test --test-isolation=none test/decider-input.test.mjs test/decider-unusual-access.test.mjs test/decider-zones.test.mjs test/notes-api.test.mjs`

정상 UUID 메모 읽기·수정은 허용, 복합 이상 사건은 추가 확인이어야 합니다.
미등록 기기·공지 수정·알 수 없는 경로·쿼리 기능 선택은 거부되어야 합니다.
최종 API에서 타인 메모는 404, 소유자 변경은 403이어야 합니다.
로컬 가상 시험은 운영 엔진 연결·배포·실제 심판 판정의 증거가 아닙니다.
