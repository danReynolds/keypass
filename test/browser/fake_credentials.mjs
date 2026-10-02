// Synthetic authenticator for tests only. NEVER imported by the helper.
import {encode} from "../../tool/browser/protocol.mjs";
import {cbor} from "./cbor.mjs";
const utf8 = new TextEncoder();
function der(raw) {
  const parts = [raw.slice(0, 32), raw.slice(32)];
  const ints = parts.map(p => {
    while (p.length > 1 && p[0] === 0) p = p.slice(1);
    if (p[0] & 128) p = new Uint8Array([0, ...p]);
    return [2, p.length, ...p];
  });
  const body = ints.flat();
  return new Uint8Array([48, body.length, ...body]).buffer;
}
export async function fakeCredentials(origin, mutation = () => {}) {
  const key = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, true, ["sign", "verify"]);
  const spki = await crypto.subtle.exportKey("spki", key.publicKey);
  const jwk = await crypto.subtle.exportKey("jwk", key.publicKey);
  const cose = cbor(new Map([[1,2],[3,-7],[-1,1],[-2,new Uint8Array(Buffer.from(jwk.x,"base64url"))],[-3,new Uint8Array(Buffer.from(jwk.y,"base64url"))]]));
  const id = new Uint8Array(32).fill(21);
  let user, domain;
  const outputs = [];
  let count = 0;
  async function response(type, options) {
    const auth = new Uint8Array(37);
    auth.set(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(domain))));
    auth[32] = type === "webauthn.create" ? 0x45 : 5;
    const client = utf8.encode(JSON.stringify({
      type, challenge: encode(options.challenge), origin, crossOrigin: false,
    }));
    return {clientDataJSON: client.buffer, authenticatorData: auth.buffer, userHandle: user.buffer};
  }
  return {
    outputs,
    async create({publicKey: options}) {
      domain = options.rp.id; user = options.user.id;
      const result = await response("webauthn.create", options);
      const auth = new Uint8Array([...new Uint8Array(result.authenticatorData),...new Uint8Array(16),0,id.length,...id,...cose]);
      result.authenticatorData = auth.buffer;
      result.attestationObject = cbor({fmt:"none",attStmt:{},authData:auth}).buffer;
      return {
        type: "public-key", rawId: id.buffer,
        response: {
          ...result, getAuthenticatorData: () => result.authenticatorData,
          getPublicKey: () => spki, getPublicKeyAlgorithm: () => -7,
        },
        getClientExtensionResults: () => ({prf: {enabled: true}}),
      };
    },
    async get({publicKey: options}) {
      const result = await response("webauthn.get", options);
      const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", result.clientDataJSON));
      const data = new Uint8Array(37 + hash.length);
      data.set(new Uint8Array(result.authenticatorData)); data.set(hash, 37);
      result.signature = der(new Uint8Array(await crypto.subtle.sign(
        {name: "ECDSA", hash: "SHA-256"}, key.privateKey, data)));
      const secret = new Uint8Array(32).fill(42);
      outputs.push(secret);
      const extension = {prf: {results: {first: secret.buffer}}};
      const credential = {type: "public-key", rawId: id.buffer, response: result,
        getClientExtensionResults: () => extension};
      mutation(credential, extension, ++count);
      return credential;
    },
  };
}
