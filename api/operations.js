import { readFile } from 'node:fs/promises';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { createOperationsHandler } from '../src/operations.mjs';

let verifier;
export default createOperationsHandler({
  verifyLogin: async authorization => {
    const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
    verifier ??= createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
    return verifier(authorization);
  },
  // 운영 결과 조회 계약이 아직 없으므로 loadRecords는 미연결로 유지합니다.
});
