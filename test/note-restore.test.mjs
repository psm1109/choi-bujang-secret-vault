import test from 'node:test';
import assert from 'node:assert/strict';
import { createNoteRestoreHandler, contentHash } from '../src/note-restore.mjs';

const ownerB = '00000000-0000-4000-8000-000000000003';
const id = '00000000-0000-4000-8000-000000000004';
function fixture() {
  // 시험 계정 B의 가상 자료만 사용합니다. 실제 사본·계정·키는 없습니다.
  const content = String.fromCodePoint(0xac00, 0xc0c1);
  const note = { id, owner_id: ownerB, title: 'B fixture', content, contentSha256: contentHash(content) };
  const backup = { schema: 'aleph.private-note-backup.v1', notes: [note] };
  const other = { id: '00000000-0000-4000-8000-000000000005', owner_id: ownerB, content: 'other-fixture' };
  const rows = new Map([[id, { ...note, content: 'damaged-fixture' }], [other.id, other]]);
  const audit = [{ event: 'previous-fixture' }];
  const state = { writes: 0, loggedIn: true, pinned: true, missing: false, loginOwner: ownerB };
  const handler = createNoteRestoreHandler({
    testOwner: ownerB,
    verifyLogin: async () => state.loggedIn ? { userId: state.loginOwner } : null,
    loadBackup: async () => {
      if (state.missing) throw new Error('backup_missing');
      const bytes = Buffer.from(JSON.stringify(backup));
      return { bytes, sha256: state.pinned ? contentHash(bytes) : '0'.repeat(64) };
    },
    restoreOne: async saved => {
      const row = rows.get(saved.id);
      if (row && row.owner_id !== saved.owner_id) return { conflict: true };
      state.writes++;
      rows.set(saved.id, structuredClone(saved));
      return { id: saved.id, owner_id: saved.owner_id, content_sha256: contentHash(saved.content) };
    },
  });
  const payload = { id, owner_id: ownerB, contentSha256: note.contentSha256 };
  const call = async (body = payload, method = 'POST') => {
    const result = { headers: {} };
    await handler({ method, headers: {}, body }, {
      setHeader(key, value) { result.headers[key] = value; },
      status(status) { result.status = status; return this; },
      json(body) { result.body = body; return this; },
    });
    return result;
  };
  return { note, backup, rows, audit, state, payload, call };
}

for (const missing of [false, true]) {
  test(`B 한 건 복원 후 ID·소유자·내용 해시 일치, 다른 메모·감사 보존: 삭제=${missing}`, async () => {
    const f = fixture();
    if (missing) f.rows.delete(id);
    const otherBefore = structuredClone(f.rows.get('00000000-0000-4000-8000-000000000005'));
    const auditBefore = structuredClone(f.audit);
    const result = await f.call();
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, f.payload);
    assert.equal(f.rows.get(id).id, f.note.id);
    assert.equal(f.rows.get(id).owner_id, f.note.owner_id);
    assert.equal(contentHash(f.rows.get(id).content), f.note.contentSha256);
    assert.deepEqual(f.rows.get('00000000-0000-4000-8000-000000000005'), otherBefore);
    assert.deepEqual(f.audit, auditBefore);
    assert.equal(f.state.writes, 1);
    assert.ok(!JSON.stringify(result).includes(f.note.content));
  });
}

for (const scenario of ['login', 'not-b', 'missing', 'pin', 'id', 'owner', 'hash', 'duplicate', 'content', 'conflict', 'method', 'extra']) {
  test(`복원 거부 시 어떤 메모도 변경하지 않음: ${scenario}`, async () => {
    const f = fixture();
    if (scenario === 'login') f.state.loggedIn = false;
    if (scenario === 'not-b') f.state.loginOwner = '00000000-0000-4000-8000-000000000007';
    if (scenario === 'missing') f.state.missing = true;
    if (scenario === 'pin') f.state.pinned = false;
    if (scenario === 'id') f.payload.id = '00000000-0000-4000-8000-000000000006';
    if (scenario === 'owner') f.payload.owner_id = '00000000-0000-4000-8000-000000000007';
    if (scenario === 'hash') f.payload.contentSha256 = '0'.repeat(64);
    if (scenario === 'duplicate') f.backup.notes.push(f.note);
    if (scenario === 'content') f.note.content += 'tampered';
    if (scenario === 'conflict') f.rows.get(id).owner_id = '00000000-0000-4000-8000-000000000007';
    if (scenario === 'extra') f.payload.content = 'client-supplied';
    const before = structuredClone([...f.rows]);
    const auditBefore = structuredClone(f.audit);
    const result = await f.call(f.payload, scenario === 'method' ? 'GET' : 'POST');
    assert.ok(result.status >= 400);
    assert.equal(f.state.writes, 0);
    assert.deepEqual([...f.rows], before);
    assert.deepEqual(f.audit, auditBefore);
  });
}
