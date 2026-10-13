// 이 화면 전용 계약은 운영 판정기 계약을 확장하지 않습니다.
export function createDeviceAccess({ onChange, fetchStatus = fetch,
  now = Date.now, schedule = setTimeout, cancel = clearTimeout, isOnline = () => true }) {
  let revision = 0;
  let registered = false;
  let timer;
  const publish = state => {
    registered = state === 'registered';
    onChange(state);
  };
  const invalidate = (state = 'unverified') => {
    revision++;
    cancel(timer);
    publish(state);
  };
  async function check(session, method = 'GET') {
    invalidate(method === 'POST' ? 'requesting' : 'checking');
    const version = revision;
    if (!isOnline()) { publish('offline'); return false; }
    if (!session?.user?.id || !session.access_token || !Number.isFinite(session.expires_at)
        || session.expires_at * 1000 <= now()) {
      publish('login_required');
      return false;
    }
    try {
      const response = await fetchStatus('/api/device-approval', {
        method, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { Authorization: `Bearer ${session.access_token}`,
          ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) },
        ...(method === 'POST' ? { body: '{}' } : {}),
      });
      const result = await response.json();
      if (version !== revision) return false;
      if (response.status === 401) { publish('login_required'); return false; }
      if (!response.ok || result?.schema !== 'aleph.device-access.v1'
          || !['registered', 'pending', 'denied', 'unregistered'].includes(result.state)
          || result.registered !== (result.state === 'registered')) {
        publish('unavailable');
        return false;
      }
      // 승인 요청 응답이나 버튼 클릭으로 자료를 열지 않습니다. 별도 상태 GET이 필요합니다.
      if (method === 'POST') {
        publish(result.state === 'pending' ? 'pending' : 'unverified');
        return false;
      }
      if (session.expires_at * 1000 <= now()) { publish('login_required'); return false; }
      publish(result.state);
      if (registered) {
        timer = schedule(() => invalidate('unverified'), Math.min(60000, session.expires_at * 1000 - now()));
      }
      return registered;
    } catch {
      if (version === revision) publish('unavailable');
      return false;
    }
  }
  return { check, invalidate, get registered() { return registered; }, get revision() { return revision; } };
}
