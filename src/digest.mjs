import { createHash, randomBytes } from 'node:crypto';

const MAX_NONCE_COUNT = 0xffffffff;

function sha256hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function hex8(value) {
  return value.toString(16).padStart(8, '0');
}

export function stageError(stage, message) {
  const error = new Error(message);
  error.stage = stage;
  return error;
}

function quoted(label, value) {
  if (/["\\\r\n]/.test(value)) throw stageError('authorize', `认证字段含有非法字符：${label}`);
  return `"${value}"`;
}

// 仅接受 RFC 7616 SHA-256 + qop=auth 的挑战，其他组合明确拒绝，不做降级。
export function parseChallenge(header) {
  if (typeof header !== 'string' || !/^\s*Digest\b/i.test(header)) {
    throw stageError('challenge', '来源未返回 Digest 认证挑战');
  }
  const fields = {};
  for (const match of header.matchAll(/([A-Za-z][A-Za-z0-9]*)\s*=\s*(?:"([^"]*)"|([^,\s]+))/g)) {
    fields[match[1].toLowerCase()] = match[2] ?? match[3];
  }
  if ((fields.algorithm ?? '').toUpperCase() !== 'SHA-256') {
    throw stageError('challenge', '来源要求了不支持的摘要算法');
  }
  const qops = (fields.qop ?? '').split(',').map(item => item.trim().toLowerCase());
  if (!qops.includes('auth')) throw stageError('challenge', '来源要求了不支持的保护方式');
  if (!fields.realm || !fields.nonce) throw stageError('challenge', '认证挑战缺少必要参数');
  return { realm: fields.realm, nonce: fields.nonce, opaque: fields.opaque ?? null, stale: fields.stale === 'true' };
}

// 计数通道：作用域为单个采集作业。cnonce 随通道生成，nc 在同一 nonce 下递增；
// 通道内请求串行发出，多个通道可合法并发，互不共用计数。
class Lane {
  #cnonce = randomBytes(12).toString('hex');
  #nonce = null;
  #count = 0;
  #queue = Promise.resolve();

  get cnonce() { return this.#cnonce; }
  get nonce() { return this.#nonce; }

  reset(nonce) {
    this.#nonce = nonce;
    this.#count = 0;
  }

  next() {
    if (this.#count >= MAX_NONCE_COUNT) throw stageError('authorize', '认证计数达到上限');
    return ++this.#count;
  }

  enqueue(task) {
    const run = this.#queue.then(task);
    this.#queue = run.catch(() => {});
    return run;
  }
}

// 会话作用域为单个授权网关来源：凭据只在本来源内使用，挑战全会话共享，
// 计数按通道隔离。凭据保存在私有字段中，不会被序列化或写进领域记录。
export class DigestSession {
  #origin;
  #username;
  #password;
  #challenge = null;

  constructor({ origin, username, password }) {
    if (!username || !password) throw new Error('缺少网关凭据');
    this.#origin = origin;
    this.#username = username;
    this.#password = password;
  }

  get origin() { return this.#origin; }
  get nonce() { return this.#challenge?.nonce ?? null; }

  lane() { return new Lane(); }

  updateChallenge(challenge) { this.#challenge = challenge; }

  authorize(method, uri, lane) {
    const challenge = this.#challenge;
    if (!challenge) return null;
    if (lane.nonce !== challenge.nonce) lane.reset(challenge.nonce);
    const nc = lane.next();
    const ha1 = sha256hex(`${this.#username}:${challenge.realm}:${this.#password}`);
    const ha2 = sha256hex(`${method}:${uri}`);
    const response = sha256hex(`${ha1}:${challenge.nonce}:${hex8(nc)}:${lane.cnonce}:auth:${ha2}`);
    const parts = [
      `username=${quoted('username', this.#username)}`,
      `realm=${quoted('realm', challenge.realm)}`,
      `nonce=${quoted('nonce', challenge.nonce)}`,
      `uri=${quoted('uri', uri)}`,
      'qop=auth',
      `nc=${hex8(nc)}`,
      `cnonce=${quoted('cnonce', lane.cnonce)}`,
      `response=${quoted('response', response)}`,
    ];
    if (challenge.opaque) parts.push(`opaque=${quoted('opaque', challenge.opaque)}`);
    parts.push('algorithm=SHA-256');
    return 'Digest ' + parts.join(', ');
  }
}
