// 운영 기기 확인·승인 계약이 제공되기 전에는 등록 상태를 생성하지 않습니다.
export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (!['GET', 'POST'].includes(request.method)) {
    response.setHeader('Allow', 'GET, POST');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  if (request.method === 'POST') {
    let origin;
    try { origin = new URL(request.headers?.origin); } catch {}
    if (!origin || origin.protocol !== 'https:' || origin.host !== request.headers?.host
        || !/^application\/json(?:\s*;|$)/iu.test(request.headers?.['content-type'] ?? '')) {
      return response.status(403).json({ error: 'FORBIDDEN' });
    }
  }
  // 입력의 토큰·기기 번호·승인 플래그·쿠키를 등록 증거로 쓰지 않습니다.
  // 요청을 접수한 척하거나 임의 등록부를 만들지 않고 연결 불가를 명시합니다.
  return response.status(503).json({ schema: 'aleph.device-access.v1',
    state: 'unavailable', registered: false, error: 'DEVICE_APPROVAL_UNAVAILABLE' });
}
