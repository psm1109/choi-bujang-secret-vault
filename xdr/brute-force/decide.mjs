import { readFile } from 'node:fs/promises';
import { loadEnvFile } from 'node:process';
import { fileURLToPath } from 'node:url';

try {
  loadEnvFile(fileURLToPath(new URL('../../.env', import.meta.url)));
} catch (error) {
  if (error.code !== 'ENOENT') throw new Error('Jev 환경 설정을 읽지 못했습니다.');
}

const { patterns } = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url), 'utf8'));
const burstName = patterns[0].name;
const sprayName = patterns[1].name;
const JEV_TIMEOUT_MS = 2000;

function decision(confidence, reason) {
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    reason,
  };
}

function numberIn(text, expression) {
  const match = text.match(expression);
  return match ? Number(match[1]) : null;
}

function evidenceFor(alert) {
  // read-alerts의 추출 결과와 실행기가 전달하는 원본 경보를 모두 받습니다.
  const description = alert?.rule?.description ?? alert?.description;
  const text = typeof description === 'string' ? description : '';
  const rawCount = alert?.data?.count;
  const parsedCount = typeof rawCount === 'number' ||
    (typeof rawCount === 'string' && /^\d+$/.test(rawCount)) ? Number(rawCount) : null;
  const failure = /실패/.test(text);
  const count = Number.isSafeInteger(parsedCount) && parsedCount >= 0 ? parsedCount
    : numberIn(text, /실패(?:가)?\s*(\d+)건/u);
  const seconds = numberIn(text, /(\d+)초\s*(?:안|동안|이내)/u);
  const minutes = numberIn(text, /(\d+)분\s*(?:안|동안|이내)/u);
  const windowMinutes = minutes ?? (seconds === null ? null : seconds / 60);
  const multiAccount = /여러 계정|서로 다른 계정|계정 이름을 바꿔|계정\s*\d+개|두 계정/u.test(text);
  const accountCount = numberIn(text, /계정\s*(\d+)개/u);
  const samePassword = /같은 비밀번호|동일한 비밀번호/u.test(text);
  const passwordVariation = /비밀번호를 한 글자씩 바꿔/u.test(text);
  const regularInterval = /같은 간격|일정한 간격/u.test(text);
  const sameSource = /같은 주소|한 주소/u.test(text)
    || typeof (alert?.data?.srcip ?? alert?.srcip) === 'string';
  const success = /성공했습니다|성공이 확인|성공으로/u.test(text);
  const normalActivity = /로그아웃|세션 유지|로그인 상태가 유지|자료실 화면이 열렸/u.test(text);
  // 부정·추정·실패/성공 건수의 모순은 확정 규칙을 건너뜁니다.
  const uncertain = /아닙|않았|없었|추정|가능성|의심|불명|미확인/u.test(text)
    || (failure && count === 0) || (success && /성공은 없습니다/u.test(text));
  return {
    failure, count, windowMinutes, multiAccount, accountCount, samePassword,
    passwordVariation, regularInterval, sameSource, success, normalActivity, uncertain,
  };
}

async function askJev(evidence, reason) {
  // 연결 계약: .env의 JEV_API_URL에 요약을 JSON POST,
  // JEV_API_KEY는 Authorization: Bearer 헤더, 응답은 { confidence: 0~1 }.
  // 자격 증명은 본문·결과에 넣지 않으며 원본 경보는 전송하지 않습니다.
  // Jev의 실제 서비스 계약이 다르면 이 어댑터에서만 맞춥니다.
  let timer;
  const controller = new AbortController();
  try {
    if (!process.env.JEV_API_URL || !process.env.JEV_API_KEY) return null;
    const url = new URL(process.env.JEV_API_URL);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    const request = async () => {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${process.env.JEV_API_KEY}`,
        },
        body: JSON.stringify({ moduleKey: 'brute-force', pattern: reason, evidence }),
        signal: controller.signal,
        redirect: 'error',
      });
      if (!response.ok) return null;
      const result = await response.json();
      return typeof result?.confidence === 'number' && Number.isFinite(result.confidence)
        && result.confidence >= 0 && result.confidence <= 1 ? result.confidence : null;
    };
    return await Promise.race([
      request(),
      new Promise(resolve => {
        timer = setTimeout(() => {
          controller.abort();
          resolve(null);
        }, JEV_TIMEOUT_MS);
      }),
    ]);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function decide(alert) {
  const evidence = evidenceFor(alert);
  const { failure, count, windowMinutes, multiAccount, accountCount, samePassword,
    passwordVariation, regularInterval, sameSource, success, normalActivity, uncertain } = evidence;

  if (!uncertain) {
    if (multiAccount && samePassword) return decision(0.98, sprayName);
    if (failure && count >= 20 && windowMinutes > 0 && windowMinutes <= 5 && sameSource) {
      return decision(0.95, burstName);
    }
    // 시간이나 동일 비밀번호가 없는 경보에는 위 두 패턴을 확정하지 않습니다.
    // 아래는 경보에 명시된 별도의 반복 대입 근거입니다.
    if (failure && passwordVariation && count >= 20) {
      return decision(0.95, '비밀번호 변형 반복 대입');
    }
    if (failure && multiAccount && accountCount >= 10 && regularInterval && sameSource) {
      return decision(0.9, '여러 계정에 일정 간격의 로그인 실패');
    }
    if (failure && count >= 30 && sameSource && !success) {
      return decision(0.9, '다량의 로그인 실패 반복');
    }
    if ((!failure && (success || normalActivity)) || (failure && count === 1 && success)) {
      return decision(0.1, '정상 인증·세션 활동');
    }
  }

  const reason = multiAccount ? sprayName
    : failure ? burstName : '판단 근거 부족';
  const confidence = await askJev(evidence, reason);
  return decision(confidence ?? 0.5, reason);
}
