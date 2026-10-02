// Independent fixture signer: Node WebCrypto/OpenSSL, never Dart or live keys.
const u8 = b => new Uint8Array(b);
const encode = b => Buffer.from(b).toString('base64url');
const utf8 = s => new TextEncoder().encode(s);
import {cbor} from "../browser/cbor.mjs";
export function der(raw) {
  const components = [raw.slice(0,32),raw.slice(32)].map(v => {
    while (v.length > 1 && v[0] === 0) v = v.slice(1);
    if (v[0] & 128) v = new Uint8Array([0,...v]);
    return [2,v.length,...v];
  }).flat();
  return new Uint8Array([48,components.length,...components]);
}
const domain='vault.example.com', origin='https://vault.example.com';
const challenge = new Uint8Array(32).fill(7), credentialId = new Uint8Array(32).fill(8), userId = new Uint8Array(32).fill(9);
const keys = await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
const jwk = await crypto.subtle.exportKey('jwk',keys.publicKey);
const publicKeyCose = cbor(new Map([[1,2],[3,-7],[-1,1],[-2,u8(Buffer.from(jwk.x,'base64url'))],[-3,u8(Buffer.from(jwk.y,'base64url'))]]));
const publicKeySpki = u8(await crypto.subtle.exportKey('spki',keys.publicKey));
const rpHash = u8(await crypto.subtle.digest('SHA-256',utf8(domain)));
const client = (type, changes={}) => utf8(JSON.stringify({type,challenge:encode(challenge),origin,crossOrigin:false,...changes}));
const auth = (flags, count=0) => { const a = new Uint8Array(37); a.set(rpHash); a[32]=flags; new DataView(a.buffer).setUint32(33,count); return a; };
const registrationAuth = new Uint8Array([...auth(0x5d),...new Uint8Array(16),0,credentialId.length,...credentialId,...publicKeyCose]);
const attestationObject = cbor({fmt:'none',attStmt:{},authData:registrationAuth});
async function assertion({flags=0x1d,count=0,changes={},suffix=[],rp=false,rawClient}={}) {
  const clientDataJSON = rawClient === undefined ? client('webauthn.get',changes) : utf8(rawClient);
  const authenticatorData = new Uint8Array([...auth(flags,count),...suffix]);
  if (rp) authenticatorData[0]^=1;
  const hash = u8(await crypto.subtle.digest('SHA-256',clientDataJSON));
  const signature = der(u8(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},keys.privateKey,new Uint8Array([...authenticatorData,...hash]))));
  return {clientDataJSON:encode(clientDataJSON),authenticatorData:encode(authenticatorData),signature:encode(signature)};
}
const variants = {};
for (const [name, options] of Object.entries({
  missingUV:{flags:0x19}, missingUP:{flags:0x1c}, badBackup:{flags:0x15}, reserved:{flags:0x3d},
  changedBackupEligibility:{flags:5}, unexpectedAttestation:{flags:0x5d}, trailing:{suffix:[0]},
  malformedExtensions:{flags:0x9d,suffix:[0xa1]}, duplicateExtensions:{flags:0x9d,suffix:[0xa2,0x61,0x78,1,0x61,0x78,2]},
  validExtensions:{flags:0x9d,suffix:cbor({'hmac-secret':new Uint8Array(32).fill(1)})},
  wrongRP:{rp:true}, wrongType:{changes:{type:'webauthn.create'}}, wrongChallenge:{changes:{challenge:encode(new Uint8Array(32))}},
  wrongOrigin:{changes:{origin:'https://other.example.com'}}, crossOrigin:{changes:{crossOrigin:true}},
  nullCrossOrigin:{changes:{crossOrigin:null}}, topOrigin:{changes:{topOrigin:origin}},
  androidOrigin:{changes:{origin:'android:apk-key-hash:'+encode(new Uint8Array(32).fill(1))}},
  counterOne:{count:1}, counterTwo:{count:2}, backupStateChanged:{flags:0x0d},
  duplicateJSON:{rawClient: '{"type":"webauthn.get","type":"webauthn.get","challenge":"'+encode(challenge)+'","origin":"'+origin+'"'},
})) variants[name]=await assertion(options);
console.log(JSON.stringify({domain,origin,challenge:encode(challenge),credentialId:encode(credentialId),userId:encode(userId),publicKeyCose:encode(publicKeyCose),publicKeySpki:encode(publicKeySpki),registration:{clientDataJSON:encode(client('webauthn.create')),attestationObject:encode(attestationObject)},assertion:await assertion(),variants}));
