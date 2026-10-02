import {createHash, generateKeyPairSync, sign} from 'node:crypto';
import {cbor} from '../browser/cbor.mjs';
const namespace='dev.example.vault';
const challenge=Buffer.alloc(32,7), input=Buffer.from('test PRF input'), id=Buffer.alloc(32,8), user=Buffer.alloc(32,9);
const sha=b=>createHash('sha256').update(b).digest();
const hash=sha(Buffer.concat([Buffer.from('Keypass direct CTAP v1\0'),Buffer.from([2]),Buffer.from(namespace+'\0'),challenge]));
const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const jwk=publicKey.export({format:'jwk'});
const cose=cbor(new Map([[1,2],[3,-7],[-1,1],[-2,new Uint8Array(Buffer.from(jwk.x,'base64url'))],[-3,new Uint8Array(Buffer.from(jwk.y,'base64url'))]]));
function auth(flags,count=0){const b=Buffer.alloc(37);sha(Buffer.from(namespace)).copy(b);b[32]=flags;b.writeUInt32BE(count,33);return b;}
function registration(extensions={'hmac-secret':true,credProtect:3},flags=0xc5){
 return Buffer.concat([auth(flags),Buffer.alloc(16),Buffer.from([0,id.length]),id,cose,cbor(extensions)]);
}
function assertion({flags=0x85, count=1, wrongRP=false, signedHash=hash, ext={'hmac-secret':new Uint8Array(48).fill(11)}}={}){
 const base=auth(flags,count);if(wrongRP)base[0]^=1;
 const data=Buffer.concat([base,cbor(ext)]);
 return {authenticatorData:data,signature:sign('sha256',Buffer.concat([data,signedHash]),privateKey)};
}
const out={namespace,challenge,input,id,user,cose,clientHash:hash,salt:sha(Buffer.concat([Buffer.from('WebAuthn PRF\0'),input])),
registration:registration(),missingPrf:registration({credProtect:3}),missingProtection:registration({'hmac-secret':true}),weakProtection:registration({'hmac-secret':true,credProtect:2}),
assertion:assertion(),missingUV:assertion({flags:0x81}),missingUP:assertion({flags:0x84}),wrongRP:assertion({wrongRP:true}),wrongHash:assertion({signedHash:Buffer.alloc(32)}),backedUp:assertion({flags:0x8d}),missingExtension:assertion({ext:{}}),shortExtension:assertion({ext:{'hmac-secret':new Uint8Array(16)}}),counterZero:assertion({count:0})};
function json(v){if(v instanceof Uint8Array)return Buffer.from(v).toString('base64url');if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,val])=>[k,json(val)]));return v;}
console.log(JSON.stringify(json(out)));
