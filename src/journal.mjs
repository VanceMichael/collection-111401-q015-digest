// 运行记录只保留定位失败阶段所需的字段。白名单之外的字段（密码、
// 认证头、nonce、cnonce、response 等可复用认证材料）一律不进入记录。
const ALLOWED_FIELDS = new Set([
  'origin', 'path', 'status', 'attempt', 'size', 'digest', 'receipt',
  'stale', 'target', 'forwardedAuth', 'authorized', 'message', 'detail',
  'device', 'endpoint',
]);

export function createJournal(sink) {
  const events = [];
  const record = (stage, fields = {}) => {
    const event = { at: new Date().toISOString(), stage };
    for (const [key, value] of Object.entries(fields)) {
      if (!ALLOWED_FIELDS.has(key) || value === undefined) continue;
      event[key] = typeof value === 'string' ? value.slice(0, 200) : value;
    }
    events.push(event);
    if (sink) sink(event);
    return event;
  };
  return { events, record };
}
