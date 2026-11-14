import { createHash, timingSafeEqual } from 'node:crypto';
export function digestHex(value){return createHash('sha256').update(value).digest('hex');}
export function checkDigest(request,state){
 const raw=request.headers.authorization??'';const fields={};
 for(const match of raw.matchAll(/([a-zA-Z]+)=(?:"([^"]*)"|([^,\s]+))/g))fields[match[1]]=match[2]??match[3];
 const nonce='nonce-'+state.generation;const stale=!!fields.nonce&&fields.nonce!==nonce;
 const challenge='Digest realm="local-detector", nonce="'+nonce+'", opaque="local", algorithm=SHA-256, qop="auth"'+(stale?', stale=true':'');
 if(!raw.startsWith('Digest ')||stale)return {ok:false,challenge};
 const ha1=digestHex('operator:local-detector:local-demo-password');const ha2=digestHex(request.method+':'+request.url);
 const expected=digestHex(`${ha1}:${nonce}:${fields.nc}:${fields.cnonce}:auth:${ha2}`);
 const actual=Buffer.from(fields.response??'');const target=Buffer.from(expected);
 const key=nonce+':'+(fields.cnonce??'');const previous=state.counts[key]??0;const count=parseInt(fields.nc,16);
 if(fields.username!=='operator'||fields.realm!=='local-detector'||fields.uri!==request.url||fields.qop!=='auth'||fields.opaque!=='local'||actual.length!==target.length||!timingSafeEqual(actual,target)||!Number.isFinite(count)||count<=previous)return {ok:false,challenge};
 state.counts[key]=count;return {ok:true};
}
