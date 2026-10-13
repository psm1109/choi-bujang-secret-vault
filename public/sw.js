const offlineCache = 'vault-offline-v1';
const offlinePage = '/offline.html';

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const response = await fetch(offlinePage, { cache: 'no-store', credentials: 'omit' });
    if (!response.ok) throw new Error('Offline page unavailable');
    const cache = await caches.open(offlineCache);
    // 고정된 공개 안내만 저장합니다. 로그인·메모·HTML 접속 화면은 저장하지 않습니다.
    await cache.put(offlinePage, response);
    await self.skipWaiting();
  })());
});
self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      if (key.startsWith('vault-offline-') && key !== offlineCache) await caches.delete(key);
    }
    await self.clients.claim();
  })());
});
self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  // API 요청은 탐색 요청이어도 가로채지 않습니다. 거부 응답도 원본 그대로 전달됩니다.
  if (request.method !== 'GET' || request.mode !== 'navigate'
      || url.origin !== self.location.origin
      || !['/', '/index.html', offlinePage].includes(url.pathname)) return;
  event.respondWith(fetch(request).catch(async () => {
    const cache = await caches.open(offlineCache);
    return (await cache.match(offlinePage))
      ?? new Response('오프라인입니다. 연결 후 자료실을 다시 열어 주세요. 기기 승인 상태는 확인할 수 없습니다.', {
        status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
      });
  }));
});
