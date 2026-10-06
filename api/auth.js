import { createClient } from '@supabase/supabase-js';

const cookieName = '__Host-vault-refresh';
const cookie = (value, age) => `${cookieName}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  // 쿠키를 사용하는 인증 작업은 같은 출처의 JSON 요청만 허용합니다.
  let origin;
  try { origin = new URL(request.headers?.origin); } catch {}
  if (!origin || origin.protocol !== 'https:' || origin.host !== request.headers?.host
      || !/^application\/json(?:\s*;|$)/iu.test(request.headers?.['content-type'] ?? '')) {
    return response.status(403).json({ error: 'FORBIDDEN' });
  }
  const action = request.query?.action;
  if (!['login', 'session', 'logout'].includes(action)) {
    return response.status(400).json({ error: 'INVALID_ACTION' });
  }
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return response.status(503).json({ error: 'AUTH_UNAVAILABLE' });
  try {
    const client = createClient(url, key, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });
    let result;
    if (action === 'login') {
      let body = request.body;
      if (typeof body === 'string') {
        try { body = JSON.parse(body); } catch { body = null; }
      }
      if (!body || typeof body.email !== 'string' || !body.email.trim()
          || body.email.length > 320 || typeof body.password !== 'string'
          || !body.password || body.password.length > 4096) {
        return response.status(400).json({ error: 'INVALID_LOGIN' });
      }
      result = await client.auth.signInWithPassword({ email: body.email.trim(), password: body.password });
    } else {
      const entry = (request.headers?.cookie ?? '').split(';')
        .map(part => part.trim()).find(part => part.startsWith(`${cookieName}=`));
      const refresh = entry ? decodeURIComponent(entry.slice(cookieName.length + 1)) : '';
      if (!refresh || refresh.length > 4096) {
        response.setHeader('Set-Cookie', cookie('', 0));
        return response.status(200).json({ session: null });
      }
      result = await client.auth.refreshSession({ refresh_token: refresh });
    }
    if (result.error || !result.data?.session) {
      if (action !== 'login') response.setHeader('Set-Cookie', cookie('', 0));
      return response.status(action === 'logout' ? 200 : 401)
        .json(action === 'logout' ? { session: null } : { error: 'UNAUTHORIZED' });
    }
    if (action === 'logout') {
      const { error } = await client.auth.signOut({ scope: 'local' });
      if (error) return response.status(503).json({ error: 'AUTH_UNAVAILABLE' });
      response.setHeader('Set-Cookie', cookie('', 0));
      return response.status(200).json({ session: null });
    }
    const session = result.data.session;
    response.setHeader('Set-Cookie', cookie(session.refresh_token, 60 * 60 * 24 * 30));
    return response.status(200).json({ session: {
      access_token: session.access_token, expires_at: session.expires_at,
      user: { id: session.user.id },
    } });
  } catch {
    return response.status(503).json({ error: 'AUTH_UNAVAILABLE' });
  }
}
