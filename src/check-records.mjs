// 가린 제출 기록의 화면용 요약입니다. 원문 응답·메모·인증값은 복사하지 않습니다.
export function summarizeCheckRecords(bundle, expectedCommit) {
  if (bundle?.schema !== 'aleph.defense.submission.v2'
      || !/^[a-f0-9]{40}$/u.test(bundle.commit ?? '')
      || (expectedCommit && bundle.commit !== expectedCommit)
      || typeof bundle.checkedAt !== 'string' || !Number.isFinite(Date.parse(bundle.checkedAt))
      || new Date(bundle.checkedAt).toISOString() !== bundle.checkedAt
      || !Array.isArray(bundle.attackAttempts) || !bundle.attackAttempts.length || bundle.attackAttempts.length > 20) {
    throw new TypeError('invalid_check_records');
  }
  const ids = new Set();
  const informationalIds = new Set(['deployment_config', 'security_header', 'browser_public_key']);
  const records = bundle.attackAttempts.map(item => {
    const informational = informationalIds.has(item?.attackId);
    if (!item || !/^[a-z0-9][a-z0-9_.-]{0,79}$/u.test(item.attackId ?? '') || ids.has(item.attackId)
        || !Number.isInteger(item.stage) || item.stage < 1 || item.stage > 11
        || !['blocked', 'breached', 'not_run'].includes(item.result)
        || (informational && item.result !== 'not_run')
        || (item.result === 'not_run' ? item.observed !== 'not_run' && (!informational
          || !/^HTTP [1-5][0-9]{2}$/u.test(item.observed ?? ''))
          : !/^HTTP [1-5][0-9]{2}(?:; jsonReady=(?:true|false))?$/u.test(item.observed ?? ''))) {
      throw new TypeError('invalid_check_record');
    }
    ids.add(item.attackId);
    return { attackId: item.attackId, stage: item.stage, observed: item.observed, result: item.result };
  });
  const blocked = records.filter(row => row.result === 'blocked').length;
  const failed = records.filter(row => row.result === 'breached').length;
  const notRun = records.filter(row => row.result === 'not_run').length;
  return { schema: 'aleph.check-records.v1', commit: bundle.commit, checkedAt: bundle.checkedAt,
    total: records.length, blocked, failed, notRun, records };
}

export function createCheckRecordsHandler({ readBundle, expectedCommit }) {
  return async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    try {
      return response.status(200).json(summarizeCheckRecords(await readBundle(), expectedCommit));
    } catch {
      return response.status(503).json({ error: 'CHECK_RECORDS_UNAVAILABLE' });
    }
  };
}
