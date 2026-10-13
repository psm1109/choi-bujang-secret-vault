import { RULE_IDS } from './decider.mjs';

const outcomes = Object.freeze({
  decision: ['allow', 'deny', 'step_up'],
  detection: ['observe', 'propose_revocation'],
  revocation: ['revoked', 'failed'],
  recovery: ['restored', 'failed'],
});

// 화면용 계약입니다. 운영 엔진 계약이나 판정기 응답을 변경하지 않습니다.
// 호출자는 서버에서 실제 API 응답을 확인한 기록만 전달해야 합니다.
// 기본 운영 연결은 없으며 로컬 시험·브라우저 입력을 결과로 만들지 않습니다.
export function operationsSnapshot(records = null, now = new Date()) {
  if (records !== null && (!Array.isArray(records) || records.length > 1000)) {
    throw new TypeError('invalid_operations_records');
  }
  const safeRecords = (records ?? []).map((record, index) => {
    if (!record || record.source !== 'actual_api'
        || !Object.hasOwn(outcomes, record.kind)
        || !outcomes[record.kind].includes(record.outcome)
        || !Number.isInteger(record.httpStatus) || record.httpStatus < 100 || record.httpStatus > 599
        || typeof record.at !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u.test(record.at)
        || !Number.isFinite(Date.parse(record.at)) || new Date(record.at).toISOString() !== record.at
        || Date.parse(record.at) > now.getTime()
        || (['revoked', 'restored'].includes(record.outcome) && (record.httpStatus < 200 || record.httpStatus >= 300))) {
      throw new TypeError('invalid_operations_record');
    }
    const safe = { number: index + 1, source: 'actual_api', kind: record.kind,
      outcome: record.outcome, at: record.at, httpStatus: record.httpStatus };
    if (record.kind === 'decision') {
      if (!Array.isArray(record.ruleIds) || record.ruleIds.some(id => !RULE_IDS.includes(id))) {
        throw new TypeError('invalid_operations_rules');
      }
      safe.ruleIds = [...new Set(record.ruleIds)];
    }
    if (record.kind === 'recovery' && record.outcome === 'restored') {
      // API/DB 대조가 끝난 버전 지문만 표시합니다. 임의 버전명·본문은 공개하지 않습니다.
      if (record.versionVerified !== true || typeof record.versionSha256 !== 'string'
          || !/^[a-f0-9]{64}$/u.test(record.versionSha256)) throw new TypeError('invalid_recovery_version');
      safe.versionSha256 = record.versionSha256;
    }
    return safe;
  });
  const summary = Object.fromEntries(Object.entries(outcomes).map(([kind, values]) => {
    const rows = safeRecords.filter(row => row.kind === kind);
    return [kind, { state: rows.length ? 'confirmed' : 'not_run',
      total: rows.length ? rows.length : null,
      counts: Object.fromEntries(values.map(value => [value,
        rows.length ? rows.filter(row => row.outcome === value).length : null])) }];
  }));
  return { schema: 'aleph.operations.v1', generatedAt: now.toISOString(),
    scope: 'returned_records_only', connected: records !== null,
    rules: [...RULE_IDS], summary, records: safeRecords };
}

export function createOperationsHandler({ verifyLogin, loadRecords = async () => null }) {
  return async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    if (!request.headers?.authorization) return response.status(401).json({ error: 'UNAUTHORIZED' });
    try {
      if (!await verifyLogin(request.headers.authorization)) return response.status(401).json({ error: 'UNAUTHORIZED' });
      // 요청 본문·쿼리에서 기록이나 집계값을 읽지 않습니다.
      return response.status(200).json(operationsSnapshot(await loadRecords()));
    } catch {
      return response.status(503).json({ error: 'OPERATIONS_UNAVAILABLE' });
    }
  };
}
