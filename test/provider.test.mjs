import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createProvider } from '../provider/server.mjs';
import { receiveCurrent } from '../src/domain.mjs';
import { Archive } from '../src/archive.mjs';
import { digestHex } from '../provider/digest.mjs';

async function controlled(provider, change) {
  const response = await fetch(provider.base + '/_control', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(change) });
  assert.equal(response.status, 200);
}

test('合法会话能领取且同一 nonce 的旧计数不能重放', async () => {
 const provider=await createProvider();
 try {
  const nonce='nonce-1';const cnonce='local-client';const nc='00000001';
  const response=digestHex(`${digestHex('operator:local-detector:local-demo-password')}:${nonce}:${nc}:${cnonce}:auth:${digestHex('GET:/protected/catalog')}`);
  const authorization=`Digest username="operator", realm="local-detector", nonce="${nonce}", uri="/protected/catalog", qop=auth, nc=${nc}, cnonce="${cnonce}", response="${response}", opaque="local", algorithm=SHA-256`;
  assert.equal((await fetch(provider.base+'/protected/catalog',{headers:{authorization}})).status,200);
  assert.equal((await fetch(provider.base+'/protected/catalog',{headers:{authorization}})).status,401);
 } finally {await provider.close();}
});

test('现有业务入口真实收存来源资料并可重新打开', async () => {
  const provider = await createProvider();
  const directory = await mkdtemp(join(tmpdir(), 'business-'));
  try {
    const result = await receiveCurrent(provider.base, directory);
    assert.ok(result);
    const archive = new Archive(directory);
    const receipts = await archive.list();
    assert.ok(receipts.length > 0);
    for (const receipt of receipts) assert.ok((await archive.read(receipt)).length > 0);
    assert.ok(provider.audit.some(request => !request.path.startsWith('/_')));
  } finally { await provider.close(); await rm(directory, { recursive: true, force: true }); }
});

test('受保护目录不因连接成功而开放', async () => {
 const provider = await createProvider();
 try {
const response=await fetch(provider.base+'/protected/catalog');assert.equal(response.status,401);assert.match(response.headers.get('www-authenticate'),/algorithm=SHA-256/);
 } finally { await provider.close(); }
});

test('换挑战会明确指出旧 nonce', async () => {
 const provider = await createProvider();
 try {
await controlled(provider,{generation:2});const response=await fetch(provider.base+'/protected/catalog',{headers:{authorization:'Digest nonce="nonce-1"'}});assert.equal(response.status,401);assert.match(response.headers.get('www-authenticate'),/stale=true/);
 } finally { await provider.close(); }
});

test('来源审计不持有认证头', async () => {
 const provider = await createProvider();
 try {
await fetch(provider.base+'/protected/catalog',{headers:{authorization:'Digest sample="secret"'}});const text=await(await fetch(provider.base+'/_audit')).text();assert.doesNotMatch(text,/secret/);
 } finally { await provider.close(); }
});
