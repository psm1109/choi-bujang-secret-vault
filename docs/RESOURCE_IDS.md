# 자료 API 자원 ID

서버는 기존 요청 주소를 기준으로 자원을 구분하고 모든 자료 API 응답의
`X-Resource-Id` 헤더에 표시합니다. JSON 응답과 기존 자료·주소·화면 메뉴는 유지합니다.

| 기존 요청 | 자원 ID |
| --- | --- |
| `GET /api/notes` | `notes` |
| `POST /api/notes` | `notes` (메모 생성 대상 구역) |
| `GET /api/notes?scope=shared` | `instructor-notices` |
| `GET`, `PUT`, `DELETE /api/notes/:id` | `notes:<소문자 UUID>` |
| 잘못된 단건 ID 또는 GET 조회 구분 | `unknown` |

기존 shared 조회 주소를 강사 공지 구역의 식별자로 사용합니다. 공지 저장 구분과
저장된 강사 권한을 확인할 수 없어 API는 shared 요청을 403으로 거부하고
`notice_permission_unverified`만 기록합니다. 본인 메모를 대신 반환하지 않습니다.
단건 ID를 함께 보내도 거부합니다. 단건 자원 ID 표시는 scope보다 우선하지만
권한 우회에 쓰이지 않습니다. 본문·헤더의 자원 ID와 role은 권한 근거로 사용하지 않습니다.
기존 로그인·소유자 검사와 자료·주소·화면 메뉴는 유지합니다.

ID는 접근 허용의 증거가 아닙니다. 판정기 v1 계약에는 resourceId 항목과 원문 쿼리가
없으므로 판정 요청·응답에 임의 필드를 추가하지 않았습니다.
후속 판정기 규칙은 [구역 규칙](ZONE_RULES.md)에 기록했습니다. 해당 판정기를 거치면
쿼리가 있는 shared 요청은 거부됩니다. 이 헤더 표는 기존 API의 자원 표시이며
판정기를 통한 접근 허용 목록이 아닙니다. 운영 엔진 연결은 확인하지 않았습니다.

편집기의 **터미널**에서 다음 명령으로 로컬 가상 API 요청을 확인합니다.

`node --test --test-isolation=none test/notes-api.test.mjs`

정상 본인 메모 요청은 기존 CRUD 결과가 유지되어야 합니다. shared 요청은
403이며 자료를 반환하지 않아야 합니다. 직접 API 우회 요청도 동일하게 검사합니다.
비로그인 요청은 401, 타인 메모 접근은 404, 소유자 변경은 403이어야 합니다.
배포 후 브라우저 개발자 도구의 **Network → 자료 요청 → Headers → Response Headers**에서
`X-Resource-Id`를 확인할 수 있습니다. 로컬 시험은 배포·운영 엔진·심판 판정이 아닙니다.
