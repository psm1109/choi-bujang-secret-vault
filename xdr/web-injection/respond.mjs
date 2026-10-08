import { createHash, randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export const XDR_RULE_ID = 'xdr_web_injection_deny';
const SCHEMA = 'aleph.xdr.web-injection.deny-rules.v1';
const TTL_MS = 10 * 60 * 1000;
let updates = Promise.resolve();

function targetHash(target) {
  if (!target || !['classId', 'projectId', 'subjectId'].every(key =>
    typeof target[key] === 'string' && target[key].length > 0 && target[key].length <= 256)
    || !/^[a-f0-9]{16}$/.test(target.deviceId)) return null;
  // 사용자 전체나 IP 대역이 아니라 엔진이 확인한 반·프로젝트·주체·기기를 함께 묶습니다.
  return createHash('sha256').update(JSON.stringify([
    target.classId, target.projectId, target.subjectId, target.deviceId,
  ])).digest('hex');
}

function validAlertId(value) {
  return typeof value === 'string' && /^[a-z][a-z0-9-]{0,63}$/u.test(value);
}

async function readRules(root) {
  let store;
  try {
    store = JSON.parse(await readFile(join(root, 'xdr', 'web-injection', 'deny-rules.json'), 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw new Error('XDR 임시 규칙 파일을 읽지 못했습니다.');
  }
  if (store?.schema !== SCHEMA || !Array.isArray(store.rules) || !store.rules.every(rule =>
    rule?.ruleId === XDR_RULE_ID && rule.moduleKey === 'web-injection'
    && validAlertId(rule.alertId) && /^[a-f0-9]{64}$/.test(rule.targetHash)
    && Number.isFinite(Date.parse(rule.createdAt)) && Number.isFinite(Date.parse(rule.expiresAt))
    && Date.parse(rule.expiresAt) > Date.parse(rule.createdAt)
    && Date.parse(rule.expiresAt) - Date.parse(rule.createdAt) <= TTL_MS)) {
    throw new Error('XDR 임시 규칙 파일 형식이 아닙니다.');
  }
  return store.rules;
}

async function saveRules(root, rules) {
  const path = join(root, 'xdr', 'web-injection', 'deny-rules.json');
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify({ schema: SCHEMA, rules }, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true });
  }
}

/**
 * resolveVerifiedTarget는 신뢰하는 서버의 경보 상관관계 조회 함수입니다.
 * ({ moduleKey, alertId }) -> { classId, projectId, subjectId, deviceId } | null
 * srcuser/srcip를 subjectId/deviceId로 바꾸거나 브라우저 입력을 전달하면 안 됩니다.
 * 이 조회 함수가 없으면 자동 차단 없이 후보와 알림만 로그에 남깁니다.
 */
export function respond(options) {
  const next = updates.then(() => apply(options));
  updates = next.catch(() => {});
  return next;
}

async function apply({ root, moduleKey = 'web-injection', decisions, resolveVerifiedTarget = async () => null,
  now = () => Date.now() }) {
  if (moduleKey !== 'web-injection') return { added: 0, skipped: 0 };
  const at = now();
  if (!Number.isFinite(at)) throw new Error('XDR 규칙 생성 시각이 아닙니다.');
  await mkdir(join(root, 'xdr', 'web-injection'), { recursive: true });
  const entries = [];
  for (const decision of decisions) {
    if (!validAlertId(decision?.alertId) || !Number.isFinite(decision.confidence)
      || decision.confidence < 0 || decision.confidence > 1
      || !['block', 'alert', 'record'].includes(decision.action)) continue;
    let hash = null;
    try {
      hash = targetHash(await resolveVerifiedTarget({ moduleKey, alertId: decision.alertId }));
    } catch {
      // 조회 실패의 원문에 개인정보가 포함될 수 있어 기록하지 않습니다.
    }
    entries.push({ decision, hash });
  }
  // 같은 실행에서 정상으로 확인된 주체·기기는 차단 후보에서 제외합니다.
  const normalTargets = new Set(entries.filter(({ decision, hash }) =>
    hash && decision.action === 'record' && decision.confidence < 0.5).map(entry => entry.hash));
  const previous = await readRules(root);
  const rules = previous.filter(rule => Date.parse(rule.expiresAt) > at
    && !normalTargets.has(rule.targetHash));
  const logs = [];
  let added = 0;
  let skipped = 0;
  for (const { decision, hash } of entries) {
    if (decision.action === 'record') continue;
    let outcome = 'notification';
    if (decision.action === 'block') {
      if (decision.confidence < 0.85 || !hash || normalTargets.has(hash)) {
        skipped += 1;
        outcome = !hash ? 'unmapped_candidate' : 'excluded_candidate';
      } else {
        const duplicate = rules.some(rule => rule.alertId === decision.alertId
          && rule.targetHash === hash);
        if (!duplicate) {
          rules.push({
            ruleId: XDR_RULE_ID, moduleKey, alertId: decision.alertId, targetHash: hash,
            createdAt: new Date(at).toISOString(), expiresAt: new Date(at + TTL_MS).toISOString(),
          });
          added += 1;
        }
        outcome = duplicate ? 'existing_rule' : 'deny_rule_added';
      }
    }
    logs.push(JSON.stringify({
      at: new Date(at).toISOString(), moduleKey, alertId: decision.alertId,
      action: decision.action, confidence: decision.confidence, outcome,
    }));
  }
  // 규칙 반영 전에 알림을 남깁니다. 설명 원문·식별자·인증 정보는 기록하지 않습니다.
  if (logs.length) await appendFile(join(root, 'xdr', 'alerts.log'), `${logs.join('\n')}\n`, { mode: 0o600 });
  if (added || rules.length !== previous.length) await saveRules(root, rules);
  return { added, skipped };
}

/** 기존 판정기는 그대로 호출하며, 활성 XDR 규칙과 정확히 일치할 때만 deny를 덧씁니다. */
export function createWebInjectionDecider({ root, baseDecide, baseRuleIds, reasonCode,
  allowedReasonCodes, now = () => Date.now() }) {
  if (typeof baseDecide !== 'function' || !Array.isArray(baseRuleIds)
    || typeof reasonCode !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/u.test(reasonCode)
    || !Array.isArray(allowedReasonCodes) || !allowedReasonCodes.includes(reasonCode)) {
    throw new Error('기존 판정기와 운영 등록부에서 허용한 XDR 거부 코드를 지정하세요.');
  }
  return {
    RULE_IDS: Object.freeze([...new Set([...baseRuleIds, XDR_RULE_ID])]),
    async decide(request) {
      const original = await baseDecide(request);
      if (original.decision === 'deny') return original;
      const hash = request?.schema === 'aleph.decision.v1' ? targetHash(request) : null;
      if (!hash) return original;
      const at = now();
      if (!Number.isFinite(at)) throw new Error('XDR 판정 시각이 아닙니다.');
      const active = (await readRules(root)).some(rule => rule.targetHash === hash
        && Date.parse(rule.createdAt) <= at && Date.parse(rule.expiresAt) > at);
      if (!active) return original;
      return {
        schema: 'aleph.decision.v1', requestId: request.requestId,
        decision: 'deny', reasonCode, ruleIds: [XDR_RULE_ID],
      };
    },
  };
}
