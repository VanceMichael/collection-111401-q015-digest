import { capture } from './client.mjs';
export async function receiveCurrent(base, directory) {
 const { bytes, receipt } = await capture(base + '/public-info', directory);
 const data = JSON.parse(bytes);
 return { receipt: receipt.id, device: data.device, endpoint: data.endpoint, credential: data.credentialName };
}
