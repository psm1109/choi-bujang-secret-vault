const PATTERNS = [
  {
    name: '요청 머리글·인자 안의 JNDI 원격 조회 구문',
    condition: '요청 머리글 값이나 주소 인자 값에 JNDI를 이용해 원격 대상을 조회하는 완전한 구문이 있는지 찾는다. 경보 설명에 CVE-2021-44228 형태와 원격 조회 구문이 명시된 경우 함께 살핀다. CVE 번호·jndi 단어·중괄호·라이브러리 이름·잘린 문자열만으로 확정하지 않으며, 이 신호만으로 서버의 취약 여부나 악용 성공을 확정하지 않는다.',
    evidence: 'NVD의 CVE-2021-44228 설명은 Log4j2의 로그 메시지·인자에 사용되는 JNDI 기능과 공격자가 제어하는 LDAP 등 원격 대상의 문제를 설명하며, MITRE ATT&CK T1190은 외부 공개 앱의 취약점 악용을 다룬다: https://nvd.nist.gov/vuln/detail/CVE-2021-44228 ; https://attack.mitre.org/techniques/T1190/',
  },
  {
    name: '알려진 취약점 점검 도구의 흔적',
    condition: '경보 설명이나 요청 정보에 알려진 취약점 점검 도구의 사용 흔적이 명시되어 있는지 찾고, CVE-2021-44228 형태의 원격 조회 구문이 동반되는지 함께 살핀다. 현재 경보에 구체적인 도구 이름은 없으므로 이름 목록을 만들지 않는다. 비슷한 수업용 프로그램 이름이나 도구 흔적만으로 공격·악용 성공을 확정하지 않는다.',
    evidence: '로컬 가상 경보 xdr/fixtures/known-cve.json의 kc-05는 취약점 점검 흔적과 CVE-2021-44228 형태의 동반을 명시하므로 이를 보조 신호로 삼으며, kc-13의 비슷한 수업용 이름은 확정 근거에서 제외한다; MITRE ATT&CK T1190은 악용의 분류 근거이며 특정 점검 도구의 증거는 아니다: https://attack.mitre.org/techniques/T1190/',
  },
];

const text = value => typeof value === 'string' ? value.slice(0, 8192) : '';

function decode(value) {
  let result = text(value);
  for (let i = 0; i < 2; i += 1) {
    try {
      const next = decodeURIComponent(result);
      if (next === result) break;
      result = next;
    } catch { break; }
  }
  return result;
}

function requestValues(alert) {
  const url = text(alert?.data?.url ?? alert?.url);
  const query = url.includes('?') ? url.slice(url.indexOf('?') + 1).split('#')[0] : '';
  // 경로와 인자 이름은 제외하고 인자 값만 살핍니다.
  const values = query.split('&').slice(0, 64).filter(part => part.includes('='))
    .map(part => decode(part.slice(part.indexOf('=') + 1).replace(/\+/g, ' ')));
  values.push(decode(alert?.data?.useragent ?? alert?.useragent));
  const headers = alert?.data?.headers ?? alert?.headers;
  if (headers && typeof headers === 'object' && !Array.isArray(headers)) {
    for (const value of Object.values(headers).slice(0, 64)) {
      for (const item of (Array.isArray(value) ? value.slice(0, 16) : [value])) {
        values.push(decode(item));
      }
    }
  }
  return values;
}

function result(confidence, names) {
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    // 고정된 패턴 이름만 반환해 경보 원문과 인증 정보를 노출하지 않습니다.
    reason: names.length ? names.join(' · ') : '일치 패턴 없음',
  };
}

// 외부 접근 없이 경보 하나를 즉시 판단합니다. 악용 성공을 판정하지 않습니다.
export function decide(alert) {
  const [lookupName, toolName] = PATTERNS.map(pattern => pattern.name);
  const description = text(alert?.rule?.description ?? alert?.description);
  const values = requestValues(alert);
  // 닫는 괄호와 원격 대상이 있는 완전한 JNDI 조회 형태만 강한 근거입니다.
  const complete = values.some(value => /\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|https?)\s*:\/\/[^\s{}/?#]+[^\s{}]*\}/iu.test(value));
  const fragment = values.some(value => /\bjndi\b|CVE-2021-44228|\$\{/iu.test(value));
  const lookupHint = /CVE-2021-44228|\bjndi\b|원격 조회|조회 (?:구문|형태)|취약점 (?:이름|목록)|라이브러리 이름|중괄호/iu.test(description);
  const toolHint = /(?:취약점\s*)?점검\s*(?:도구|흔적)/u.test(description);
  const negatedTool = /점검\s*(?:도구|흔적)[은는이가]?\s*(?:없|아니)|점검 도구.*(?:사용하지|실행하지)/u.test(description);
  const definiteTool = toolHint && !negatedTool && !/비슷|수업용|의심|추정|미확인/u.test(description);
  const names = [];
  if (complete || fragment || lookupHint) names.push(lookupName);
  if (toolHint && !negatedTool) names.push(toolName);
  if (complete) return result(definiteTool ? 0.98 : 0.95, names);
  // 단독 단어·잘린 구문·도구 흔적은 검토 알림으로 남깁니다.
  if (names.length) return result(definiteTool ? 0.65 : 0.5, names);
  return result(0.1, []);
}
