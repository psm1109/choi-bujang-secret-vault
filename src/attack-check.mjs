// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step === 11) return runOperationsChecks(config);
  if ([3, 4, 5, 6, 7, 8, 9, 10].includes(config.step)) return runStep3Checks(config);
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

// BYTE BACK 표본의 제출 실행 기록 메타데이터를 사용합니다.
// https://github.com/ChoiTimo/byteback-sample-pass/blob/main/src/attack-check.mjs
async function runOperationsChecks(config) {
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || !app.hostname.endsWith('.vercel.app')) throw new Error('실제 배포 주소를 확인해 주세요.');
  const results = [];
  for (const [attackId, path, expected, accepts] of [
    ['deployment_config', '/aleph.json', '배포 설정의 단계·원본 API·허용 경로 일치', async response => {
      const data = await response.json();
      return response.ok && data.step === config.step && data.originalApiUrl === config.originalApiUrl
        && JSON.stringify(data.allowedRoutes) === JSON.stringify(config.allowedRoutes);
    }],
    ['security_header', '/', '첫 화면 X-Content-Type-Options: nosniff', async response => {
      await response.body?.cancel();
      return response.ok && response.headers.get('x-content-type-options') === 'nosniff';
    }],
    ['browser_public_key', '/', '첫 화면 코드에 Supabase 공개 키·anon JWT·SDK 없음', async response => {
      const html = await response.text();
      return response.ok && !/sb_publishable_|eyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.|@supabase\/supabase-js/u.test(html);
    }],
  ]) {
    let response;
    try {
      response = await fetch(new URL(path, app), { method: 'GET', redirect: 'error', cache: 'no-store',
        signal: AbortSignal.timeout(5000), alephEvidence: { caseId: attackId, requestKey: 'read' } });
      const matches = await accepts(response);
      results.push({ attackId, stage: 5, expected, observed: `HTTP ${response.status}`,
        result: matches ? 'blocked' : 'breached' });
    } catch {
      // 상태 응답까지 확인했으나 형식 검사에 실패한 경우와 응답 부재를 구분합니다.
      results.push({ attackId, stage: 5, expected, observed: response ? `HTTP ${response.status}` : 'not_run',
        result: response ? 'breached' : 'not_run' });
    }
  }
  for (const [attackId, stage, expected] of [
    ['static_note_read', 2, '비로그인 GET /data.json: HTTP 404'],
    ['anonymous_note_list', 3, '비로그인 GET /api/notes: HTTP 401'],
    ['anonymous_shared_read', 3, '비로그인 shared GET: HTTP 401'],
    ['anonymous_note_read', 3, '비로그인 단건 GET: HTTP 401'],
    ['anonymous_note_create', 3, '비로그인 POST: HTTP 401'],
    ['anonymous_note_update', 4, '비로그인 PUT: HTTP 401'],
    ['anonymous_note_delete', 4, '비로그인 DELETE: HTTP 401'],
    ['resource_zone_fixtures', 8, '구역 규칙의 운영 판정 확인'],
    ['detection_fixtures', 9, '운영 사건 전달과 폭주 탐지 확인'],
    ['revocation_and_timing', 9, '특정 기기 실제 회수·시간·정상 기기 유지 확인'],
    ['restore_backup_verification', 10, '검증된 사본 복원·버전·자료 보존 확인'],
    ['authenticated_and_database_checks', 5, '실제 계정 CRUD·소유자 검사·원본 API 직접 접근 거부'],
    ['app_manifest', 11, '배포 manifest의 앱 이름·시작 주소·아이콘 확인'],
    ['device_status_endpoint', 11, '서버 기기 상태 확인'],
    ['device_request_endpoint', 11, '승인 요청만으로 권한 부여 금지'],
    ['device_approval_live_flow', 11, '실제 등록 확인 뒤 정상 화면·승인 전 자료 차단'],
  ]) results.push({ attackId, stage, expected, observed: 'not_run', result: 'not_run' });
  return results;
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
  if (config.step >= 5) {
    for (const path of ['/aleph.json', '/']) {
      try {
        const response = await fetch(new URL(path, app), {
          redirect: 'error', signal: AbortSignal.timeout(5000), cache: 'no-store',
        });
        if (path === '/aleph.json') {
          const data = await response.json();
          const matches = response.ok && data.step === config.step
            && data.originalApiUrl === config.originalApiUrl
            && JSON.stringify(data.allowedRoutes) === JSON.stringify(config.allowedRoutes);
          results.push({ attackId: 'deployment_config',
            expected: '배포 설정에 쿼리 없는 원본 HTTPS 주소와 허용 자료 경로 6개 포함',
            observed: `실제 GET /aleph.json HTTP ${response.status}; 설정 ${matches ? '일치' : '불일치'}; 배포 단계 ${Number.isInteger(data.step) ? data.step : '미확인'}; 배포 커밋 ${/^[a-f0-9]{40}$/iu.test(data.commit ?? '') ? data.commit : '미확인'}` });
        } else {
          const html = await response.text();
          results.push({ attackId: 'security_header', expected: '첫 화면 X-Content-Type-Options: nosniff',
            observed: `실제 GET / HTTP ${response.status}; nosniff ${response.ok && response.headers.get('x-content-type-options') === 'nosniff' ? '확인' : '미확인'}` });
          results.push({ attackId: 'browser_public_key', expected: '첫 화면 코드에 Supabase 공개 키·anon JWT·SDK 없음',
            observed: `실제 GET / HTTP ${response.status}; ${response.ok && !/sb_publishable_|eyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.|@supabase\/supabase-js/u.test(html) ? '검사 패턴 없음' : '조건 미충족'}; 응답 본문 미기록` });
        }
      } catch {
        results.push({ attackId: path === '/aleph.json' ? 'deployment_config' : 'first_page_checks',
          expected: path === '/aleph.json' ? '배포 설정의 원본 API 주소·허용 경로 확인' : '첫 화면 보안 헤더·공개 키 부재 확인',
          observed: '요청 시도했으나 응답 확인 실패; 미확인' });
      }
    }
  }
  for (const [attackId, method, path, expectedStatus] of checks) {
    // 제출 격리는 읽기 요청만 허용합니다. 쓰기 시험을 보낸 척하지 않습니다.
    if (!['GET', 'HEAD'].includes(method)) {
      results.push({ attackId, expected: `비로그인 ${method} ${path}: HTTP ${expectedStatus}`, observed: 'not_run' });
      continue;
    }
    let observed;
    try {
      const response = await fetch(new URL(path, app), {
        method, redirect: 'error', signal: AbortSignal.timeout(5000),
      });
      observed = `실제 비로그인 요청 HTTP ${response.status}; ${response.status === expectedStatus ? '기대 상태 일치' : '기대 상태 불일치'}; 응답 본문 미기록`;
      await response.body?.cancel();
    } catch {
      observed = '요청 시도했으나 통신 실패: HTTP 결과 미확인';
    }
    results.push({ attackId, expected: `비로그인 ${method} ${path}: HTTP ${expectedStatus}`, observed });
  }
  if (config.step !== 11) results.push({ attackId: 'authenticated_a_crud', expected: '정상 A 로그인으로 추가·조회·수정·삭제, 삭제 후 GET 404',
    observed: '실제 배포 미실행; 로컬 가상 요청 시험만 통과. 실제 심판 판정 아님' });
  if (config.step >= 4 && config.step !== 11) {
    for (const [attackId, expected] of [
      ['authenticated_b_crud', '정상 B의 자기 메모 CRUD'],
      ['cross_owner_access', 'A/B의 상대 메모 GET·PUT·DELETE는 404'],
      ['owner_transfer', 'PUT의 타인 owner_id는 403; POST는 검증된 ID로 저장'],
      ['database_rls', config.step >= 5
        ? 'anon·authenticated 직접 권한 없음; service_role CRUD 유지'
        : 'authenticated는 자기 행만 CRUD; anon은 권한 없음'],
    ]) results.push({ attackId, expected, observed: '미실행; 실제 계정·DB 정책 시험 및 심판 판정 미확인' });
  }
  if (config.step >= 5 && config.step !== 11) results.push({
    attackId: 'original_api_direct_access',
    expected: '원본 learning_notes API의 anon·authenticated 직접 자료 접근 거부',
    observed: '직접 API 요청 미실행; 사용자 제공 권한 화면에서 anon·authenticated 모두 false, service_role CRUD true 확인. 실제 심판 판정 아님',
  });
  if (config.step >= 6 && config.step < 8) {
    const { decide } = await import('./decider.mjs');
    const { fixtureRequests } = await import('../scripts/fixture-7.mjs');
    const { normal, suspicious } = fixtureRequests();
    for (const [attackId, registered, expected] of [
      ['registered_device_read', true, '로컬 등록 기기 가상 요청: allow'],
      ['unregistered_device_read', false, '로컬 미등록 기기 가상 요청: deny·device_not_registered'],
    ]) {
      const response = await decide({ ...normal, deviceRegistered: registered });
      results.push({ attackId, expected,
        observed: `로컬 가상 요청 실행: ${response.decision}·${response.reasonCode}; 실제 미등록 기기 공격은 심판 담당, 운영 접속·심판 판정 미확인` });
    }
    if (config.step === 7) {
      for (const [attackId, request, expected] of [
        ['compound_access_review', suspicious, '로컬 복합 가상 사건: step_up·step_up_required'],
        ['reconfirmed_fixture_read', { ...suspicious,
          stepUp: { verified: true, authAgeSeconds: 60 } }, '로컬 재확인 가상 요청: allow·approved'],
      ]) {
        const response = await decide(request);
        results.push({ attackId, expected,
          observed: `로컬 가상 요청 실행: ${response.decision}·${response.reasonCode}; 실제 자료 차단·새 로그인 시각 검증 미실행, 심판 판정 미확인` });
      }
    }
  }
  if ([8, 9, 10, 11].includes(config.step)) {
    const { decide } = await import('./decider.mjs');
    const { fixtureRequests } = await import('../scripts/fixture-7.mjs');
    const { normal, suspicious } = fixtureRequests();
    const checks = [
      ['read', normal, 'allow'],
      ['update', { ...normal, method: 'PUT', route: 'PUT /notes/:id' }, 'allow'],
      ['list', { ...normal, path: '/notes', route: 'GET /notes' }, 'deny'],
      ['device', { ...normal, deviceRegistered: false }, 'deny'],
      ['step_up', suspicious, 'step_up'],
      ['reconfirmed', { ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } }, 'allow'],
      ...['POST', 'PUT', 'PATCH', 'DELETE'].map(method => [method.toLowerCase(), {
        ...normal, method, route: `${method} /instructor-notices/:id`,
        path: normal.path.replace('/notes/', '/instructor-notices/'),
      }, 'deny']),
    ];
    const observations = [];
    for (const [name, request, expected] of checks) {
      const response = await decide(request);
      observations.push(`${name}:${response.decision}${response.decision === expected ? '' : '(불일치)'}`);
    }
    results.push({ attackId: 'resource_zone_fixtures',
      expected: '로컬 단건 읽기·수정 허용, 전체 목록·공지 쓰기·미등록 거부, 복합 추가 확인 및 재확인 허용',
      observed: `로컬 가상 요청 실행 ${observations.join(', ')}; 운영 연결·심판 미확인` });
  }
  if ([9, 10, 11].includes(config.step)) {
    results.push({ attackId: 'detection_fixtures',
      expected: '원본 폭주 및 확장 복합 사건만 각 계약의 회수 제안, 정상 사건 observe',
      // node:util을 쓰는 로컬 연습기는 npm run detect:test에서만 실행합니다.
      observed: 'not_run' });
    results.push({ attackId: 'revocation_and_timing',
      expected: '심판이 특정 가상 기기 실제 회수·경과 시간·정상 기기 유지를 확인',
      observed: '미실행; 회수 API·권한 변경 없음; 실제 회수·시간·정상 기기 운영 유지와 S09_NO_PROPOSAL 해소 미확인' });
  }
  if ([10, 11].includes(config.step)) {
    if (config.restoreRoute !== '/api/notes/restore') throw new Error('복원 경로 설정을 구현과 대조해 주세요.');
    results.push({ attackId: 'restore_backup_verification',
      expected: '비로그인 복원 401; 안전 사본 재검증·버전·범위 확인 후 B 한 건 복원 및 다른 자료·감사 보존',
      observed: 'not_run' });
  }
  return results;
}
