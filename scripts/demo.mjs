import { createProvider } from '../provider/server.mjs';
import { connectGateway, receiveCurrent } from '../src/domain.mjs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const directory = await mkdtemp(join(tmpdir(), 'collection-'));
const provider = await createProvider();
try {
  const gateway = await connectGateway(provider.base, {
    username: process.env.GATEWAY_USERNAME ?? 'operator',
    password: process.env.GATEWAY_PASSWORD ?? 'local-demo-password',
  });
  const jobs = await Promise.all([1, 2, 3].map(() => receiveCurrent(gateway, directory)));
  console.log(JSON.stringify({
    service: 'digest',
    device: gateway.device,
    jobs,
    journal: gateway.journal.events,
    requests: provider.audit,
  }, null, 2));
} finally {
  await provider.close();
  await rm(directory, { recursive: true, force: true });
}
