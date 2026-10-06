import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
await mkdir(resolve(root, 'public'), { recursive: true });
await rm(output, { force: true });
console.log('공개 data.json을 제거했습니다. 자료는 서버 API로 조회합니다.');
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
