import { Archive } from './archive.mjs';
import { parseChallenge, stageError } from './digest.mjs';

const MAX_BODY = 8 * 1024 * 1024;
const MAX_AUTH_ATTEMPTS = 4;
const MAX_TRANSPORT_ATTEMPTS = 3;
const MAX_REDIRECTS = 5;

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// 收件出处只保留来源地址本身，去掉可能夹带凭据的用户信息和片段。
export function sanitizeSourceUrl(value) {
  const url = new URL(value);
  url.username = '';
  url.password = '';
  url.hash = '';
  return url.toString();
}

async function readLimited(response, limitMessage) {
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > MAX_BODY) throw stageError('receive', limitMessage);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

// 短时断连做有界重试，失败阶段标记为 transport，不会无限重试。
async function fetchWithRetry(fetchImpl, url, init, options) {
  const { journal, timeoutMs = 5000 } = options;
  const target = new URL(url);
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await fetchImpl(url, { redirect: 'manual', signal: AbortSignal.timeout(timeoutMs), ...init });
    } catch (error) {
      journal?.record('transport', { origin: target.origin, path: target.pathname, attempt, message: error.message });
      if (attempt >= MAX_TRANSPORT_ATTEMPTS) throw stageError('transport', `来源连接失败：${error.message}`);
      await delay(60 * attempt);
    }
  }
}

export async function capture(url, directory, options = {}) {
  const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(5000), ...options });
  if (!response.ok) throw new Error(`来源领取失败：${response.status}`);
  const bytes = await readLimited(response, '单份人工领取超过当前收件上限');
  const source = {
    url: sanitizeSourceUrl(url),
    status: response.status,
    type: response.headers.get('content-type'),
    etag: response.headers.get('etag'),
  };
  const archive = new Archive(directory);
  const receipt = await archive.save(bytes, source);
  return { bytes, receipt };
}

export async function requestJson(url, options = {}) {
  const { fetchImpl = fetch, stage = 'receive' } = options;
  const response = await fetchWithRetry(fetchImpl, url, {}, options);
  if (!response.ok) throw stageError(stage, `来源领取失败：${response.status}`);
  try {
    return await response.json();
  } catch {
    throw stageError(stage, '来源返回内容无法解析');
  }
}

export async function sessionRequest(session, initialUrl, options = {}) {
  const lane = options.lane ?? session.lane();
  return lane.enqueue(() => performRequest(session, initialUrl, lane, options));
}

async function performRequest(session, initialUrl, lane, options) {
  const { fetchImpl = fetch, journal } = options;
  let url = new URL(initialUrl);
  let authorized = session.nonce !== null;
  let authAttempts = 0;
  let redirects = 0;
  while (true) {
    const uri = url.pathname + url.search;
    const headers = {};
    let usedNonce = null;
    if (authorized) {
      usedNonce = session.nonce;
      const authorization = session.authorize('GET', uri, lane);
      if (authorization) headers.authorization = authorization;
    }
    journal?.record('request', { origin: url.origin, path: url.pathname, authorized });
    const response = await fetchWithRetry(fetchImpl, url.toString(), { headers }, options);
    if (response.status === 401) {
      await response.arrayBuffer().catch(() => {});
      const challenge = parseChallenge(response.headers.get('www-authenticate'));
      journal?.record('challenge', { origin: url.origin, path: url.pathname, stale: challenge.stale });
      if (authorized && challenge.nonce === usedNonce && !challenge.stale) {
        throw stageError('authorize', '来源拒绝了当前凭据');
      }
      session.updateChallenge(challenge);
      authAttempts += 1;
      if (authAttempts > MAX_AUTH_ATTEMPTS) throw stageError('authorize', '认证挑战次数超出上限');
      authorized = true;
      continue;
    }
    if (response.status >= 300 && response.status < 400 && response.headers.get('location')) {
      await response.arrayBuffer().catch(() => {});
      redirects += 1;
      if (redirects > MAX_REDIRECTS) throw stageError('redirect', '重定向次数超出上限');
      const target = new URL(response.headers.get('location'), url);
      // 认证材料只送往会话所属来源；跨来源重定向继续跟随但不带认证头。
      const forward = authorized && target.origin === session.origin;
      journal?.record('redirect', {
        origin: url.origin,
        path: url.pathname,
        target: target.origin + target.pathname,
        forwardedAuth: forward,
      });
      url = target;
      authorized = forward;
      continue;
    }
    return { response, url: url.toString() };
  }
}

export async function authorizedCapture(session, url, directory, options = {}) {
  const journal = options.journal;
  const initial = new URL(url);
  try {
    if (initial.origin !== session.origin) throw stageError('authorize', '凭据不能用于其他来源');
    const { response, url: finalUrl } = await sessionRequest(session, url, options);
    if (!response.ok) throw stageError('receive', `来源领取失败：${response.status}`);
    const bytes = await readLimited(response, '单份领取超过当前收件上限');
    const finalParts = new URL(finalUrl);
    const source = {
      url: sanitizeSourceUrl(finalUrl),
      status: response.status,
      type: response.headers.get('content-type'),
      etag: response.headers.get('etag'),
    };
    let receipt;
    try {
      receipt = await new Archive(directory).save(bytes, source);
    } catch (error) {
      throw stageError('archive', `收件存储失败：${error.message}`);
    }
    journal?.record('receive', {
      origin: finalParts.origin,
      path: finalParts.pathname,
      status: response.status,
      size: bytes.length,
      digest: receipt.digest,
      receipt: receipt.id,
    });
    return { bytes, receipt };
  } catch (error) {
    journal?.record(error.stage ?? 'failure', { origin: initial.origin, path: initial.pathname, detail: error.message });
    throw error;
  }
}
