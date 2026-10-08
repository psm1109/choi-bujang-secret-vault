import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL('../fixtures/web-injection.json', import.meta.url);
const REDACTED = '[비밀값 숨김]';

// 비밀 필드는 선택하지 않습니다. 선택한 문자열에 자격 증명 형태가
// 섞인 경우에도 그 필드 전체를 가려 값이 일부라도 출력되지 않게 합니다.
function safeText(value) {
  if (typeof value !== 'string') return null;
  const looksSecret = /(?:password|passwd|pwd|token|secret|api[_ -]?key|private[_ -]?key|authorization|비밀번호|토큰|비밀키|개인키)\s*["']?\s*[:=]\s*\S/iu.test(value)
    || /\bBearer\s+\S|-----BEGIN [\w ]*PRIVATE KEY-----/iu.test(value)
    || /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/u.test(value)
    || /\b(?:sk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]+\b/u.test(value)
    || /[a-z][a-z0-9+.-]*:\/\/[^\s/]+:[^\s/]+@/iu.test(value)
    || /[A-Za-z0-9_+/=-]{32,}/u.test(value);
  return looksSecret ? REDACTED : value;
}

export function extractAlerts(fixture) {
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'web-injection' || !Array.isArray(fixture.alerts)) {
    throw new Error('웹 주입 경보 묶음 형식이 아닙니다.');
  }
  // 누락된 항목은 null로 남겨 경보 하나당 출력 한 줄을 유지합니다.
  return fixture.alerts.map(alert => ({
    timestamp: safeText(alert?.timestamp),
    srcip: safeText(alert?.data?.srcip),
    srcuser: safeText(alert?.data?.srcuser),
    level: typeof alert?.rule?.level === 'number' && Number.isFinite(alert.rule.level)
      ? alert.rule.level : null,
    description: safeText(alert?.rule?.description),
  }));
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  return extractAlerts(fixture);
}

const isMain = process.argv[1]
  && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    for (const alert of await readAlerts()) {
      process.stdout.write(`${JSON.stringify(alert)}\n`);
    }
  } catch {
    // JSON 파싱 오류에 포함될 수 있는 원본 내용은 출력하지 않습니다.
    console.error('경보를 읽지 못했습니다. 파일과 경보 묶음 형식을 확인하세요.');
    process.exitCode = 1;
  }
}
