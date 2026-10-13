import { readFile } from 'node:fs/promises';
import { createCheckRecordsHandler } from '../src/check-records.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

export default createCheckRecordsHandler({
  expectedCommit: process.env.VERCEL_GIT_COMMIT_SHA,
  readBundle: async () => {
    try {
      const text = await readFile(new URL('../artifacts/submission.json', import.meta.url), 'utf8');
      if (Buffer.byteLength(text) > 64 * 1024) throw new Error('records_too_large');
      return JSON.parse(text);
    } catch (error) {
      // 제출 파일은 Git에서 제외됩니다. 없을 때만 읽기 점검을 새로 실행합니다.
      if (error.code !== 'ENOENT') throw error;
      const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
      if (config.step !== 11) throw new Error('wrong_step');
      const identityResponse = await fetch(new URL('/aleph.json', config.publicAppUrl), {
        method: 'GET', redirect: 'error', signal: AbortSignal.timeout(5000), cache: 'no-store',
      });
      const deployed = identityResponse.ok ? await identityResponse.json() : null;
      if (!/^[a-f0-9]{40}$/u.test(deployed?.commit ?? '') || deployed.step !== config.step
          || (process.env.VERCEL_GIT_COMMIT_SHA && deployed.commit !== process.env.VERCEL_GIT_COMMIT_SHA)) {
        throw new Error('deployment_identity_unavailable');
      }
      const attackAttempts = await runAttackChecks(config);
      if (!attackAttempts.some(item => item.result !== 'not_run')) throw new Error('live_probe_unavailable');
      return { schema: 'aleph.defense.submission.v2', commit: deployed.commit,
        checkedAt: new Date().toISOString(), attackAttempts };
    }
  },
});
