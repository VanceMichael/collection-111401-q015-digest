import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createProvider } from '../provider/server.mjs';
import { connectGateway, receiveCurrent } from '../src/domain.mjs';
import { DigestSession } from '../src/digest.mjs';
import { capture, sanitizeSourceUrl, sessionRequest } from '../src/client.mjs';
import { createJournal } from '../src/journal.mjs';
import { Archive } from '../src/archive.mjs';

const credentials = { username: 'operator', password: 'local-demo-password' };

async function controlled(provider, change) {
  const response = await fetch(provider.base + '/_control', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(change),
  });
  assert.equal(response.status, 200);
}

async function withWorkspace(run) {
  const provider = await createProvider();
  const directory = await mkdtemp(join(tmpdir(), 'session-'));
  try {
    await run(provider, directory);
  } finally {
    await provider.close();
    await rm(directory, { recursive: true, force: true });
  }
}

test('多个采集作业共享授权入口，轮换挑战后仍能持续收取', async () => withWorkspace(async (provider, directory) => {
  const journal = createJournal();
  const gateway = await connectGateway(provider.base, credentials, { journal });
  await receiveCurrent(gateway, directory);
  await controlled(provider, { generation: 2 });
  const jobs = await Promise.all([1, 2, 3, 4].map(() => receiveCurrent(gateway, directory)));
  assert.equal(new Set(jobs.map(job => job.receipt)).size, 4);
  const archive = new Archive(directory);
  const receipts = await archive.list();
  assert.equal(receipts.length, 5);
  for (const receipt of receipts) assert.ok((await archive.read(receipt)).length > 0);
  assert.ok(receipts.every(receipt => receipt.source.url.includes('/protected/catalog')));
  const rotated = Object.keys(provider.state.counts).filter(key => key.startsWith('nonce-2:'));
  assert.equal(rotated.length, 4);
  assert.ok(journal.events.some(event => event.stage === 'challenge' && event.stale === true));
  assert.ok(journal.events.filter(event => event.stage === 'receive').length >= 5);
}));

test('错误凭据快速失败且不陷入无休止重试', async () => withWorkspace(async (provider, directory) => {
  const journal = createJournal();
  const gateway = await connectGateway(provider.base, { username: 'operator', password: 'wrong-password' }, { journal });
  await assert.rejects(() => receiveCurrent(gateway, directory), error => {
    assert.equal(error.stage, 'authorize');
    return true;
  });
  const attempts = provider.audit.filter(entry => entry.path === '/protected/catalog');
  assert.equal(attempts.length, 2);
  assert.ok(journal.events.some(event => event.stage === 'authorize'));
}));

test('短时断连经有界重试后完成领取', async () => withWorkspace(async (provider, directory) => {
  let failures = 2;
  const flaky = async (url, init) => {
    if (String(url).includes('/protected/') && failures > 0) {
      failures -= 1;
      throw new TypeError('fetch failed');
    }
    return fetch(url, init);
  };
  const journal = createJournal();
  const gateway = await connectGateway(provider.base, credentials, { fetch: flaky, journal });
  const result = await receiveCurrent(gateway, directory);
  assert.ok(result.receipt);
  assert.equal(failures, 0);
  assert.ok(journal.events.filter(event => event.stage === 'transport').length >= 2);
}));

test('持续断连时有界重试并标明失败阶段', async () => withWorkspace(async (provider, directory) => {
  let calls = 0;
  const down = async () => {
    calls += 1;
    throw new TypeError('fetch failed');
  };
  const gateway = await connectGateway(provider.base, credentials);
  await assert.rejects(() => receiveCurrent(gateway, directory, { fetch: down }), error => {
    assert.equal(error.stage, 'transport');
    return true;
  });
  assert.equal(calls, 3);
}));

test('跨来源重定向不携带认证材料', async () => withWorkspace(async (provider, directory) => {
  await controlled(provider, { mode: 'redirect' });
  const gatewayOrigin = new URL(provider.base).origin;
  const outside = [];
  const spy = async (url, init) => {
    const target = new URL(url);
    if (target.origin !== gatewayOrigin) {
      outside.push({ url: String(url), headers: init?.headers ?? {} });
      return new Response('外来源资料', { status: 200, headers: { 'content-type': 'text/plain' } });
    }
    return fetch(url, init);
  };
  const journal = createJournal();
  const gateway = await connectGateway(provider.base, credentials, { fetch: spy, journal });
  const result = await receiveCurrent(gateway, directory);
  assert.ok(result.receipt);
  assert.equal(outside.length, 1);
  assert.ok(!('authorization' in outside[0].headers));
  const redirect = journal.events.find(event => event.stage === 'redirect');
  assert.equal(redirect.forwardedAuth, false);
  const archive = new Archive(directory);
  const receipt = (await archive.list()).find(item => item.id === result.receipt);
  assert.deepEqual(await archive.read(receipt), Buffer.from('外来源资料'));
}));

test('同源重定向按新地址重新计算认证，查询部分参与签名', async () => {
  const session = new DigestSession({ origin: 'http://gw.local', ...credentials });
  const calls = [];
  const fake = async (url, init) => {
    calls.push({ url: String(url), headers: init?.headers ?? {} });
    if (calls.length === 1) {
      return new Response('{}', {
        status: 401,
        headers: { 'www-authenticate': 'Digest realm="local-detector", nonce="nonce-7", opaque="local", algorithm=SHA-256, qop="auth"' },
      });
    }
    if (calls.length === 2) return new Response('', { status: 302, headers: { location: '/protected/catalog?part=2' } });
    return new Response('{"records":[]}', { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const { response } = await sessionRequest(session, 'http://gw.local/protected/catalog', { fetchImpl: fake });
  assert.equal(response.status, 200);
  assert.equal(calls.length, 3);
  assert.match(calls[1].headers.authorization, /uri="\/protected\/catalog"/);
  assert.match(calls[2].headers.authorization, /uri="\/protected\/catalog\?part=2"/);
});

test('不支持的挑战参数被明确拒绝且不降级', async () => {
  for (const challenge of [
    'Digest realm="local-detector", nonce="nonce-1", algorithm=MD5, qop="auth"',
    'Digest realm="local-detector", nonce="nonce-1", algorithm=SHA-256, qop="auth-int"',
  ]) {
    const session = new DigestSession({ origin: 'http://gw.local', ...credentials });
    let calls = 0;
    const fake = async () => {
      calls += 1;
      return new Response('{}', { status: 401, headers: { 'www-authenticate': challenge } });
    };
    await assert.rejects(() => sessionRequest(session, 'http://gw.local/protected/catalog', { fetchImpl: fake }), error => {
      assert.equal(error.stage, 'challenge');
      return true;
    });
    assert.equal(calls, 1);
  }
});

test('运行记录与收存文件不携带密码或可复用认证材料', async () => withWorkspace(async (provider, directory) => {
  const journal = createJournal();
  const gateway = await connectGateway(provider.base, credentials, { journal });
  await controlled(provider, { generation: 2 });
  const result = await receiveCurrent(gateway, directory);
  const archive = new Archive(directory);
  const exposed = JSON.stringify({ events: journal.events, receipts: await archive.list(), result, session: gateway.session });
  assert.doesNotMatch(exposed, /local-demo-password/);
  assert.doesNotMatch(exposed, /cnonce|authorization|response"|nonce-\d/);
}));

test('收件出处不保留地址中夹带的凭据', async () => withWorkspace(async (provider, directory) => {
  assert.equal(
    sanitizeSourceUrl('http://operator:local-demo-password@127.0.0.1:8080/protected/catalog?part=1#frag'),
    'http://127.0.0.1:8080/protected/catalog?part=1',
  );
  const { receipt } = await capture(provider.base + '/public-info', directory);
  assert.equal(receipt.source.url, provider.base + '/public-info');
  assert.doesNotMatch(JSON.stringify(receipt), /local-demo-password/);
}));
