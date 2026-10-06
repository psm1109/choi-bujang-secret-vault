import { createClient } from '@supabase/supabase-js';
import { readFileSync } from 'node:fs';
import { createLoginVerifier } from '../src/verify-login.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
let verifyLogin;

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
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
    const { data, error } = await supabase.from('learning_notes')
      .select('title,content').order('title');
    if (error || !Array.isArray(data)) {
      return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
    }
    return response.status(200).json({
      notes: data.map(({ title, content }) => ({ title, content })),
    });
  } catch {
    // 설정값이나 Supabase 오류 원문을 응답·로그에 남기지 않습니다.
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
