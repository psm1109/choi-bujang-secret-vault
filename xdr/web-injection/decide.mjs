import { PATTERNS } from './patterns.mjs';

const [sqlName, scriptName, pathName] = PATTERNS.map(pattern => pattern.name);
const text = value => typeof value === 'string' ? value.slice(0, 8192) : '';

function requestArguments(alert) {
  const url = text(alert?.data?.url ?? alert?.url);
  const query = url.includes('?') ? url.slice(url.indexOf('?') + 1).split('#')[0] : '';
  // 인자 값만 검사합니다. 경로·인자 이름·계정 이름은 공격 근거가 아닙니다.
  return query.split('&').filter(part => part.includes('=')).map(part => {
    let value = part.slice(part.indexOf('=') + 1).replace(/\+/g, ' ');
    for (let i = 0; i < 2; i += 1) {
      try {
        const decoded = decodeURIComponent(value);
        if (decoded === value) break;
        value = decoded;
      } catch { break; }
    }
    return value;
  });
}

// 같은 폴더의 순수 .mjs만 사용합니다. 환경변수·통신·Jev는 필요하지 않습니다.
export function decide(alert) {
  const description = text(alert?.rule?.description ?? alert?.description);
  const args = requestArguments(alert);
  const result = (action, confidence, names) => ({
    action, confidence, reason: names.join(' · '),
  });
  const strong = [];
  const partial = [];
  const uncertain = /의심|추정|가능성|불명|미확인|처럼 보이/u.test(description);
  const negated = /(?:구문|표기|표식|태그|이탈|삽입|공격)[은는이가]?\s*(?:없|아니|아닙)|탐지되지|확인되지/u.test(description);
  const repeated = !/반복[^.]*?(?:없|않|아니)/u.test(description)
    && (Number(alert?.data?.count ?? alert?.count) >= 2
      || /(?:[2-9]|\d{2,})\s*(?:번|건)|반복됐|반복된|연속 요청/u.test(description));
  const sqlDescription = /SQL\s*(?:구문|표식)|데이터베이스 조회를 이어 붙/u.test(description);
  const scriptDescription = /스크립트\s*(?:삽입|표식|표기|태그)/u.test(description);
  const pathDescription = /경로 이탈|여러 단계.*(?:거슬러|상위)|상위 경로 이동/u.test(description);

  const sqlComplete = args.some(value => /\bunion\s+(?:all\s+)?select\s+\S+|\bselect\s+.+?\s+from\s+\w+|['"]\s*(?:or|and)\s+(?:\d+\s*=\s*\d+|['"][^'"]*['"]\s*=\s*['"][^'"]*['"])/iu.test(value));
  const scriptComplete = args.some(value => /<script\b[^>]*>[\s\S]*?<\/script\s*>|<[^>]+\bon\w+\s*=\s*[^>]+>/iu.test(value));
  const pathComplete = args.some(value => /(?:\.\.[/\\]){2,}/u.test(value));

  for (const [name, complete, described, fragment] of [
    [sqlName, sqlComplete, sqlDescription, args.some(value => /['"]|\bunion\s+select\b|\bselect\s+.+\s+from\b/iu.test(value)) || /따옴표/u.test(description)],
    [scriptName, scriptComplete, scriptDescription, args.some(value => /<\/?script\b|javascript\s*:/iu.test(value))],
    [pathName, pathComplete, pathDescription, args.some(value => /\.\.[/\\]/u.test(value))],
  ]) {
    if (complete || (described && repeated && !uncertain && !negated)) strong.push(name);
    else if ((described && !negated) || fragment) partial.push(name);
  }

  if (strong.length) return result('block', 0.95, strong);
  if (partial.length) return result('alert', 0.6, partial);
  // 패턴 밖의 구분자나 종류가 명시되지 않은 주입 신호는 차단 근거로 승격하지 않습니다.
  if (!negated && /주입처럼|이상한 검색|구분 문자|명령 구분자/u.test(description)) {
    return result('alert', 0.5, ['일치 패턴 없음: 불완전한 주입 신호']);
  }
  return result('record', 0.1, ['일치 패턴 없음']);
}
