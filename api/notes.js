import { createClient } from '@supabase/supabase-js';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createLoginVerifier } from '../src/verify-login.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
let verifyLogin;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const noteResponse = ({ id, title, content }) => ({ id, title, body: content });

// 서버 라우터의 경로 인자와 조회 구분만 사용합니다. 요청 헤더·본문의 자원 ID는 믿지 않습니다.
function resourceIdForRequest(request) {
  const { id, scope } = request.query ?? {};
  if (id !== undefined) {
    return typeof id === 'string' && UUID.test(id) ? `notes:${id.toLowerCase()}` : 'unknown';
  }
  if (request.method === 'GET' && scope === 'shared') return 'instructor-notices';
  if (request.method === 'GET' && scope !== undefined) return 'unknown';
  return 'notes';
}

export default async function handler(request, response) {
  // 고정된 코드만 기록합니다. 사용자 ID·자료 ID·본문·토큰·DB 오류는 남기지 않습니다.
  const deny = (status, error, reason) => {
    console.warn('notes_denied', reason);
    response.setHeader('X-Denial-Reason', reason);
    return response.status(status).json({ error });
  };
  response.setHeader('Cache-Control', 'no-store');
  // 거부 응답도 같은 자원 구분을 표시하며 기존 JSON 응답 형식은 유지합니다.
  response.setHeader('X-Resource-Id', resourceIdForRequest(request));
  const id = request.query?.id;
  const methods = id === undefined ? ['GET', 'POST'] : ['GET', 'PUT', 'DELETE'];
  if (!methods.includes(request.method)) {
    response.setHeader('Allow', methods.join(', '));
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  const authorization = request.headers?.authorization;
  if (typeof authorization !== 'string' || !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(authorization)
      || authorization.length > 8192) {
    return deny(401, 'UNAUTHORIZED', 'login_required');
  }
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  }
  try {
    verifyLogin ??= createLoginVerifier({ config, supabaseSecretKey: secretKey });
    const identity = await verifyLogin(authorization);
    if (!identity) return deny(401, 'UNAUTHORIZED', 'login_invalid');
    const supabase = createClient(url, secretKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });
    if (id !== undefined && (typeof id !== 'string' || !UUID.test(id))) {
      return response.status(400).json({ error: 'INVALID_ID' });
    }
    const scope = request.query?.scope;
    if (scope !== undefined && scope !== 'shared') return response.status(400).json({ error: 'INVALID_SCOPE' });
    // 공지의 저장 구분·강사 권한을 확인하기 전에는 다른 구역 자료로 대체하지 않습니다.
    // 단건 ID와 함께 제출하거나 메뉴·본문 role을 위조해도 동일하게 거부합니다.
    if (scope === 'shared') return deny(403, 'FORBIDDEN', 'notice_permission_unverified');
    if (request.method === 'POST' || request.method === 'PUT') {
      let payload = request.body;
      if (typeof payload === 'string') {
        try { payload = JSON.parse(payload); } catch { payload = null; }
      }
      if (!payload || Array.isArray(payload) || typeof payload.title !== 'string'
          || !payload.title.trim() || payload.title.length > 200
          || typeof payload.body !== 'string' || payload.body.length > 20000
          || (request.method === 'POST' && payload.id !== undefined
            && (typeof payload.id !== 'string' || !UUID.test(payload.id)))) {
        return response.status(400).json({ error: 'INVALID_NOTE' });
      }
      if (request.method === 'POST') {
        const createdId = payload.id ?? randomUUID();
        const { error } = await supabase.from('learning_notes').insert({
          id: createdId, title: payload.title, content: payload.body, owner_id: identity.userId,
        });
        if (error) return response.status(error.code === '23505' ? 409 : 503)
          .json({ error: error.code === '23505' ? 'NOTE_EXISTS' : 'NOTES_UNAVAILABLE' });
        return response.status(201).json({ id: createdId });
      }
      if (Object.hasOwn(payload, 'owner_id') && payload.owner_id !== identity.userId) {
        return deny(403, 'FORBIDDEN', 'owner_change_forbidden');
      }
      // 기존 행을 소유자로 제한하고 새 행의 소유자도 검증된 ID로 고정합니다.
      const { data, error } = await supabase.from('learning_notes')
        .update({ title: payload.title, content: payload.body, owner_id: identity.userId })
        .eq('id', id).eq('owner_id', identity.userId)
        .select('id,title,content').maybeSingle();
      if (error) return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
      if (!data) return deny(404, 'NOT_FOUND', 'not_found_or_not_owner');
      return response.status(200).json(noteResponse(data));
    }
    if (request.method === 'DELETE') {
      const { data, error } = await supabase.from('learning_notes').delete()
        .eq('id', id).eq('owner_id', identity.userId).select('id').maybeSingle();
      if (error) return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
      if (!data) return deny(404, 'NOT_FOUND', 'not_found_or_not_owner');
      return response.status(200).json({ id: data.id });
    }
    if (id !== undefined) {
      const { data, error } = await supabase.from('learning_notes')
        .select('id,title,content').eq('id', id).eq('owner_id', identity.userId).maybeSingle();
      if (error) return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
      if (!data) return deny(404, 'NOT_FOUND', 'not_found_or_not_owner');
      return response.status(200).json(noteResponse(data));
    }
    const query = supabase.from('learning_notes').select('id,title,content')
      .eq('owner_id', identity.userId);
    const { data, error } = await query.order('title');
    if (error || !Array.isArray(data)) return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
    return response.status(200).json(data.map(noteResponse));
  } catch {
    // 설정값이나 Supabase 오류 원문을 응답·로그에 남기지 않습니다.
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
