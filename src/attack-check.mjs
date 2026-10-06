// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if ([3, 4, 5].includes(config.step)) return runStep3Checks(config);
  if (config.step !== 1) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}


// 실제 배포에 보낸 비로그인 요청만 기록합니다. 응답 본문은 기록하지 않습니다.
async function runStep3Checks(config) {
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || !app.hostname.endsWith('.vercel.app')) {
    throw new Error('실제 배포 주소를 확인해 주세요.');
  }
  const id = '00000000-0000-4000-8000-000000000000';
  const checks = [
    ['static_note_read', 'GET', '/data.json', 404],
    ['anonymous_note_list', 'GET', '/api/notes', 401],
    ['anonymous_shared_read', 'GET', '/api/notes?scope=shared', 401],
    ['anonymous_note_read', 'GET', `/api/notes/${id}`, 401],
    ['anonymous_note_create', 'POST', '/api/notes', 401],
    ['anonymous_note_update', 'PUT', `/api/notes/${id}`, 401],
    ['anonymous_note_delete', 'DELETE', `/api/notes/${id}`, 401],
  ];
  const results = [];
  for (const [attackId, method, path, expectedStatus] of checks) {
    let observed;
    try {
      const response = await fetch(new URL(path, app), {
        method, redirect: 'error', signal: AbortSignal.timeout(5000),
        ...(['POST', 'PUT'].includes(method) ? {
          headers: { 'Content-Type': 'application/json' }, body: '{}',
        } : {}),
      });
      observed = `실제 비로그인 요청 HTTP ${response.status}; ${response.status === expectedStatus ? '기대 상태 일치' : '기대 상태 불일치'}; 응답 본문 미기록`;
      await response.body?.cancel();
    } catch {
      observed = '요청 시도했으나 통신 실패: HTTP 결과 미확인';
    }
    results.push({ attackId, expected: `비로그인 ${method} ${path}: HTTP ${expectedStatus}`, observed });
  }
  results.push({ attackId: 'authenticated_a_crud', expected: '정상 A 로그인으로 추가·조회·수정·삭제, 삭제 후 GET 404',
    observed: '실제 배포 미실행; 로컬 가상 요청 시험만 통과. 실제 심판 판정 아님' });
  if (config.step >= 4) {
    for (const [attackId, expected] of [
      ['authenticated_b_crud', '정상 B의 자기 메모 CRUD'],
      ['cross_owner_access', 'A/B의 상대 메모 GET·PUT·DELETE는 404'],
      ['owner_transfer', 'PUT의 타인 owner_id는 403; POST는 검증된 ID로 저장'],
      ['database_rls', config.step === 5
        ? 'anon·authenticated 직접 권한 없음; service_role CRUD 유지'
        : 'authenticated는 자기 행만 CRUD; anon은 권한 없음'],
    ]) results.push({ attackId, expected, observed: '미실행; 실제 계정·DB 정책 시험 및 심판 판정 미확인' });
  }
  if (config.step === 5) results.push({
    attackId: 'original_api_direct_access',
    expected: '원본 learning_notes API의 anon·authenticated 직접 자료 접근 거부',
    observed: '직접 API 요청 미실행; 사용자 제공 권한 화면에서 anon·authenticated 모두 false, service_role CRUD true 확인. 실제 심판 판정 아님',
  });
  return results;
}
