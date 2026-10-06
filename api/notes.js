import { createClient } from '@supabase/supabase-js';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createLoginVerifier } from '../src/verify-login.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
let verifyLogin;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const noteResponse = ({ id, title, content }) => ({ id, title, body: content });

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  const id = request.query?.id;
  const methods = id === undefined ? ['GET', 'POST'] : ['GET', 'PUT', 'DELETE'];
  if (!methods.includes(request.method)) {
    response.setHeader('Allow', methods.join(', '));
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  const authorization = request.headers?.authorization;
  if (typeof authorization !== 'string' || !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(authorization)
      || authorization.length > 8192) {
    return response.status(401).json({ error: 'UNAUTHORIZED' });
  }
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  }
  try {
    verifyLogin ??= createLoginVerifier({ config, supabaseSecretKey: secretKey });
    const identity = await verifyLogin(authorization);
    if (!identity) return response.status(401).json({ error: 'UNAUTHORIZED' });
    const supabase = createClient(url, secretKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });
    if (id !== undefined && (typeof id !== 'string' || !UUID.test(id))) {
      return response.status(400).json({ error: 'INVALID_ID' });
    }
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
        return response.status(403).json({ error: 'FORBIDDEN' });
      }
      // 기존 행을 소유자로 제한하고 새 행의 소유자도 검증된 ID로 고정합니다.
      const { data, error } = await supabase.from('learning_notes')
        .update({ title: payload.title, content: payload.body, owner_id: identity.userId })
        .eq('id', id).eq('owner_id', identity.userId)
        .select('id,title,content').maybeSingle();
      if (error) return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
      if (!data) return response.status(404).json({ error: 'NOT_FOUND' });
      return response.status(200).json(noteResponse(data));
    }
    if (request.method === 'DELETE') {
      const { data, error } = await supabase.from('learning_notes').delete()
        .eq('id', id).eq('owner_id', identity.userId).select('id').maybeSingle();
      if (error) return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
      if (!data) return response.status(404).json({ error: 'NOT_FOUND' });
      return response.status(200).json({ id: data.id });
    }
    if (id !== undefined) {
      const { data, error } = await supabase.from('learning_notes')
        .select('id,title,content').eq('id', id).eq('owner_id', identity.userId).maybeSingle();
      if (error) return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
      if (!data) return response.status(404).json({ error: 'NOT_FOUND' });
      return response.status(200).json(noteResponse(data));
    }
    const scope = request.query?.scope;
    if (scope !== undefined && scope !== 'shared') return response.status(400).json({ error: 'INVALID_SCOPE' });
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
