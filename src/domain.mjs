import { DigestSession, stageError } from './digest.mjs';
import { authorizedCapture, requestJson } from './client.mjs';
import { createJournal } from './journal.mjs';

// 连接授权网关：读取公开说明，建立可共享的 Digest 会话。
// 凭据由配置注入，只保存在会话私有字段中，不进入领域记录。
export async function connectGateway(base, credentials, options = {}) {
  const origin = new URL(base).origin;
  const journal = options.journal ?? createJournal();
  const session = new DigestSession({ origin, username: credentials?.username, password: credentials?.password });
  try {
    const info = await requestJson(origin + '/public-info', {
      fetchImpl: options.fetch,
      journal,
      timeoutMs: options.timeoutMs,
      stage: 'public-info',
    });
    if (typeof info?.endpoint !== 'string' || !info.endpoint.startsWith('/')) {
      throw stageError('public-info', '来源公开说明缺少受保护目录地址');
    }
    journal.record('public-info', { origin, status: 200, device: info.device, endpoint: info.endpoint });
    return {
      base: origin,
      device: info.device,
      endpoint: info.endpoint,
      credentialName: info.credentialName,
      session,
      journal,
      fetchImpl: options.fetch,
      timeoutMs: options.timeoutMs,
    };
  } catch (error) {
    journal.record(error.stage ?? 'failure', { origin, path: '/public-info', detail: error.message });
    throw error;
  }
}

// 多个采集作业共享同一网关入口并发调用；每个作业默认使用独立计数通道，
// 也可通过 options.lane 传入自己的通道以复用计数。
export async function receiveCurrent(gateway, directory, options = {}) {
  const { receipt } = await authorizedCapture(gateway.session, gateway.base + gateway.endpoint, directory, {
    journal: gateway.journal,
    fetchImpl: options.fetch ?? gateway.fetchImpl,
    timeoutMs: options.timeoutMs ?? gateway.timeoutMs,
    lane: options.lane,
  });
  return { receipt: receipt.id, device: gateway.device, endpoint: gateway.endpoint, credential: gateway.credentialName };
}
