const titles = { decision: '판정 결과', detection: '탐지 사건', revocation: '회수 상태', recovery: '복구 버전' };
const labels = { allow: '허용', deny: '거부', step_up: '추가 확인', observe: '관찰',
  propose_revocation: '회수 제안', revoked: '회수 완료', failed: '실패', restored: '복구 확인' };
const outcomes = { decision: ['allow', 'deny', 'step_up'], detection: ['observe', 'propose_revocation'],
  revocation: ['revoked', 'failed'], recovery: ['restored', 'failed'] };

export function createOperationsPanel({ root, fetchReport = fetch, online = () => navigator.onLine !== false }) {
  const message = root.querySelector('[data-message]');
  const content = root.querySelector('[data-content]');
  const button = root.querySelector('#refresh-operations');
  let session = null;
  let revision = 0;
  const clear = text => { revision++; content.replaceChildren(); message.textContent = text; button.disabled = !session?.access_token; };
  const element = (tag, text) => { const node = root.ownerDocument.createElement(tag); node.textContent = text; return node; };
  const setSession = value => {
    session = value;
    button.disabled = !session?.access_token;
    clear(session?.access_token ? '결과를 확인하려면 작전실 새로고침을 누르세요.' : '로그인 후 서버 기록을 확인할 수 있습니다.');
  };
  async function refresh() {
    clear('서버 기록을 확인하는 중입니다.');
    if (!session?.access_token || !online()) { clear('확인 불가 — 로그인과 연결 상태를 확인하세요.'); return; }
    const version = revision;
    button.disabled = true;
    try {
      const response = await fetchReport('/api/operations', { headers: { Authorization: `Bearer ${session.access_token}` },
        credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
      const report = await response.json();
      if (version !== revision) return;
      if (!response.ok || report?.schema !== 'aleph.operations.v1'
          || !Array.isArray(report.rules) || !Array.isArray(report.records)
          || report.records.some(row => !row || !Object.hasOwn(titles, row.kind)
            || !outcomes[row.kind].includes(row.outcome))) throw new Error();
      // 화면의 숫자는 표시하는 가린 기록에서 다시 계산해 서버 요약과 대조합니다.
      for (const kind of Object.keys(titles)) {
        const rows = report.records.filter(row => row.kind === kind);
        const summary = report.summary?.[kind];
        if (!summary || summary.total !== (rows.length || null)
            || summary.state !== (rows.length ? 'confirmed' : 'not_run')
            || !summary.counts || Object.keys(summary.counts).sort().join(',') !== [...outcomes[kind]].sort().join(',')
            || rows.some(row => row.source !== 'actual_api')) throw new Error();
        for (const [outcome, count] of Object.entries(summary.counts)) {
          if (count !== (rows.length ? rows.filter(row => row.outcome === outcome).length : null)) throw new Error();
        }
      }
      const fragment = root.ownerDocument.createDocumentFragment();
      fragment.append(element('h3', `구현된 판정 규칙 ${report.rules.length}개`), element('p', report.rules.join(' · ')));
      for (const [kind, title] of Object.entries(titles)) {
        const summary = report.summary[kind];
        fragment.append(element('h3', title), element('p', summary.state === 'not_run'
          ? '미실행 — 확인된 운영 결과 없음'
          : `실제 API 응답에서 확인 ${summary.total}건 · ${Object.entries(summary.counts).map(([key, value]) => `${labels[key]} ${value}건`).join(' · ')}`));
      }
      fragment.append(element('h3', `가린 서버 기록 ${report.records.length}건 (이번 응답 범위)`));
      const list = element('ul', '');
      for (const row of report.records) {
        list.append(element('li', `#${row.number} · ${row.at} · ${titles[row.kind]} · HTTP ${row.httpStatus} · ${labels[row.outcome]}`
          + (row.ruleIds ? ` · ${row.ruleIds.join(', ')}` : '')
          + (row.versionSha256 ? ` · 검증된 복구 버전 SHA-256 ${row.versionSha256}` : '')));
      }
      fragment.append(list);
      if (version !== revision) return;
      content.replaceChildren(fragment);
      message.textContent = `${report.generatedAt} · ${report.connected ? '반환된 기록만 집계했습니다.' : '운영 결과 조회는 미연결입니다.'} 총공세·심판 통과를 뜻하지 않습니다.`;
    } catch {
      if (version === revision) clear('확인 불가 — API 응답이 없거나 요약과 기록이 일치하지 않습니다.');
    } finally {
      if (version === revision) button.disabled = !session?.access_token;
    }
  }
  button.addEventListener('click', () => void refresh());
  setSession(null);
  return { setSession, refresh, invalidate: () => clear('확인 불가 — 연결 후 새로고침하세요.') };
}
