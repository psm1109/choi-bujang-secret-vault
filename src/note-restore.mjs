import { createHash } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const SHA = /^[0-9a-f]{64}$/u;
export const contentHash = content => createHash('sha256').update(content, 'utf8').digest('hex');

// 서버 전용 의존성만 사용하고 본문·ID·인증값을 로그에 남기지 않습니다.
export function createNoteRestoreHandler({ verifyLogin, loadBackup, restoreOne, testOwner }) {
  return async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    try {
      const identity = await verifyLogin(request.headers?.authorization);
      if (!identity) return response.status(401).json({ error: 'UNAUTHORIZED' });
      if (!UUID.test(testOwner ?? '')) return response.status(503).json({ error: 'RESTORE_UNAVAILABLE' });
      if (identity.userId !== testOwner) return response.status(403).json({ error: 'FORBIDDEN' });
      let payload = request.body;
      if (typeof payload === 'string') { try { payload = JSON.parse(payload); } catch { payload = null; } }
      if (!payload || Array.isArray(payload) || Object.keys(payload).sort().join(',') !== 'contentSha256,id,owner_id'
          || typeof payload.id !== 'string' || !UUID.test(payload.id)
          || typeof payload.owner_id !== 'string' || !UUID.test(payload.owner_id)
          || typeof payload.contentSha256 !== 'string' || !SHA.test(payload.contentSha256)) {
        return response.status(400).json({ error: 'INVALID_RESTORE' });
      }
      if (payload.owner_id !== identity.userId) return response.status(403).json({ error: 'FORBIDDEN' });
      const { bytes, sha256 } = await loadBackup();
      if (!Buffer.isBuffer(bytes) || bytes.length > 1024 * 1024 || !SHA.test(sha256 ?? '')
          || contentHash(bytes) !== sha256) return response.status(503).json({ error: 'BACKUP_INVALID' });
      const backup = JSON.parse(bytes.toString('utf8'));
      if (backup.schema !== 'aleph.private-note-backup.v1' || !Array.isArray(backup.notes)) {
        return response.status(503).json({ error: 'BACKUP_INVALID' });
      }
      const matches = backup.notes.filter(note => note?.id === payload.id);
      if (matches.length !== 1) return response.status(409).json({ error: 'BACKUP_TARGET_MISMATCH' });
      const note = matches[0];
      if (note.owner_id !== testOwner || note.owner_id !== payload.owner_id
          || typeof note.title !== 'string' || !note.title.trim() || note.title.length > 200
          || typeof note.content !== 'string' || note.content.length > 20000
          || note.contentSha256 !== payload.contentSha256 || contentHash(note.content) !== note.contentSha256) {
        return response.status(409).json({ error: 'BACKUP_TARGET_MISMATCH' });
      }
      // DB 함수가 트랜잭션 안에서 소유자 제한·한 건 쓰기·복원 결과 해시 대조를 수행합니다.
      const result = await restoreOne(note);
      if (result?.conflict) return response.status(409).json({ error: 'RESTORE_CONFLICT' });
      if (!result || result.id !== note.id || result.owner_id !== note.owner_id
          || result.content_sha256 !== note.contentSha256) return response.status(503).json({ error: 'RESTORE_UNAVAILABLE' });
      return response.status(200).json({ id: result.id, owner_id: result.owner_id, contentSha256: result.content_sha256 });
    } catch {
      return response.status(503).json({ error: 'RESTORE_UNAVAILABLE' });
    }
  };
}
