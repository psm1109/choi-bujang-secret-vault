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
  // 공식 계약: model/state/questions를 보내고 answers의 noul(공격일 확률)을 읽습니다.
  // Choice/Score의 confidence는 정상 판단의 확신도도 높을 수 있어 차단 점수로 쓰지 않습니다.
  // JEV_API_KEY는 Authorization: Bearer 헤더에만 사용합니다.
  // 자격 증명은 본문·결과에 넣지 않으며 원본 경보는 전송하지 않습니다.
  const failure = (code, status) => {
    // 원본 오류·응답·URL·API 키는 출력하지 않습니다.
    console.error(`[Jev] ${code}${status === undefined ? '' : ` (HTTP ${status})`}: alert/0.5 기본값 사용`);
    return null;
  };
  let timer;
  const controller = new AbortController();
  try {
    if (!process.env.JEV_API_URL || !process.env.JEV_API_KEY) return failure('configuration_missing');
    let url;
    try { url = new URL(process.env.JEV_API_URL); } catch { return failure('url_invalid'); }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return failure('url_invalid');
    const request = async () => {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${process.env.JEV_API_KEY}`,
        },
        body: JSON.stringify({
          model: 'jev-latest',
          state: { moduleKey: 'brute-force', candidatePattern: reason, evidence },
          questions: {
            is_brute_force: {
              type: 'noul',
              instructions: '이 경보의 evidence는 무차별 로그인 공격을 뒷받침하는가? '
                + 'candidatePattern은 확정된 사실이 아니라 검토할 후보 패턴 이름이다. '
                + '누락된 시간 범위나 동일 비밀번호를 추정하지 말고, 소수의 실패 뒤 성공 등 정상 근거도 고려하라.',
              criteria: {
                true: '반복적인 비밀번호 추측 또는 여러 계정에 동일 비밀번호를 대입한 공격 근거가 있다.',
                false: '정상 인증 활동이거나 공격으로 판단할 근거가 부족하다.',
              },
            },
          },
        }),
        signal: controller.signal,
        redirect: 'error',
      });
      if (!response.ok) return failure('http_error', response.status);
      let result;
      try { result = await response.json(); } catch { return failure('response_invalid'); }
      const answer = result?.answers?.is_brute_force;
      const confidence = answer?.noul;
      return answer?.type === 'noul' && typeof confidence === 'number' && Number.isFinite(confidence)
        && confidence >= 0 && confidence <= 1 ? confidence : failure('response_invalid');
    };
    return await Promise.race([
      request(),
      new Promise(resolve => {
        timer = setTimeout(() => {
          controller.abort();
          resolve(failure('timeout'));
        }, JEV_TIMEOUT_MS);
      }),
    ]);
  } catch {
    return failure(controller.signal.aborted ? 'timeout' : 'network_error');
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
