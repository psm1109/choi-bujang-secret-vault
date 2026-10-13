const labels = { blocked: '기대 조건 일치', breached: '기대 조건 불일치', not_run: '미실행' };

export function createCheckRecordsPanel({ root, fetchRecords = fetch }) {
  const message = root.querySelector('[data-check-message]');
  const content = root.querySelector('[data-check-content]');
  const button = root.querySelector('button');
  let revision = 0;
  const clear = text => { revision++; content.replaceChildren(); message.textContent = text; button.disabled = false; };
  const element = (tag, value) => { const node = root.ownerDocument.createElement(tag); node.textContent = value; return node; };
  async function refresh() {
    clear('서버 점검 기록을 확인하는 중입니다.');
    const version = revision;
    button.disabled = true;
    try {
      const response = await fetchRecords('/api/checks', { method: 'GET', cache: 'no-store',
        credentials: 'omit', redirect: 'error' });
      const report = await response.json();
      if (version !== revision) return;
      if (!response.ok || report?.schema !== 'aleph.check-records.v1' || !Array.isArray(report.records)
          || report.records.some(row => !row || !Object.hasOwn(labels, row.result))) throw new Error();
      const blocked = report.records.filter(row => row.result === 'blocked').length;
      const failed = report.records.filter(row => row.result === 'breached').length;
      const notRun = report.records.filter(row => row.result === 'not_run').length;
      if (report.total !== report.records.length || report.blocked !== blocked
          || report.failed !== failed || report.notRun !== notRun) throw new Error();
      const fragment = root.ownerDocument.createDocumentFragment();
      fragment.append(element('p', `점검 항목 ${report.total}건 · 기대 조건 일치 ${blocked}건 · 불일치 ${failed}건 · 미실행 ${notRun}건`));
      const list = element('ul', '');
      for (const row of report.records) {
        list.append(element('li', `${row.attackId} · ${row.stage}단계 · ${row.observed} · ${labels[row.result]}`));
      }
      fragment.append(list);
      content.replaceChildren(fragment);
      message.textContent = `기록 커밋 ${report.commit} · 확인 시각 ${report.checkedAt} · 자기 점검 요약이며 심판 통과·41종 방어 수가 아닙니다.`;
    } catch {
      if (version === revision) clear('확인 불가 — 기록 없음·API 미연결·커밋 또는 집계 불일치입니다. 수치는 표시하지 않습니다.');
    } finally { if (version === revision) button.disabled = false; }
  }
  button.addEventListener('click', () => void refresh());
  clear('서버 점검 기록을 새로고침하세요.');
  return { refresh, invalidate: () => clear('확인 불가 — 연결 후 다시 확인하세요.') };
}

if (typeof document !== 'undefined') {
  const root = document.querySelector('#check-records');
  if (root) {
    const panel = createCheckRecordsPanel({ root });
    window.addEventListener('offline', panel.invalidate);
    void panel.refresh();
  }
}
