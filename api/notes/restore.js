import { readFile } from 'node:fs/promises';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { createNoteRestoreHandler } from '../../src/note-restore.mjs';

export default async function handler(request, response) {
  let verifier;
  const restore = createNoteRestoreHandler({
    testOwner: process.env.NOTE_RESTORE_TEST_OWNER_ID,
    verifyLogin: async authorization => {
      if (!authorization) return null;
      const config = JSON.parse(await readFile(new URL('../../aleph.config.json', import.meta.url), 'utf8'));
      verifier ??= createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
      return verifier(authorization);
    },
    loadBackup: async () => ({
      bytes: await readFile(process.env.NOTE_RESTORE_BACKUP_PATH),
      sha256: process.env.NOTE_RESTORE_BACKUP_SHA256,
    }),
    restoreOne: async note => {
      const client = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      });
      const { data, error } = await client.rpc('restore_test_note', {
        target_id: note.id, target_owner: note.owner_id, saved_title: note.title,
        saved_content: note.content, saved_hash: note.contentSha256,
      });
      if (error) throw new Error('restore_unavailable');
      return data?.[0] ?? { conflict: true };
    },
  });
  return restore(request, response);
}
