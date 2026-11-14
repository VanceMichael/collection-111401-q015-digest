import { checkDigest } from './digest.mjs';
export const initialState = { generation: 1, mode: 'normal', clock: 1000, counts: {} };
export async function stop(state) {  }
export async function routes(context) {
 const { request, url, body, payload, state, json, text, binary } = context;

 if(url.pathname==='/public-info')return json({device:'detector-1',endpoint:'/protected/catalog',credentialName:'local-device-operator',algorithm:'SHA-256'});
 if(url.pathname==='/protected/catalog'){
  const result=checkDigest(request,state);if(!result.ok)return json({error:'需要授权会话'},401,{'www-authenticate':result.challenge});
  if(state.mode==='redirect')return text('',302,{location:'http://localhost:1/outside'});
  return json({device:'detector-1',records:[{id:'inspection-1',value:3}]});
 }

}
