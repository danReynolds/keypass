import {encode, decode} from "./protocol.mjs";

const utf8 = new TextEncoder();
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const join = (a, b) => { const out = new Uint8Array(a.length + b.length); out.set(a); out.set(b, a.length); return out; };

// Strict short-form DER ES256 signature conversion for WebCrypto's IEEE P1363.
export function es256Signature(bytes) {
  if (bytes.length < 8 || bytes.length > 72 || bytes[0] !== 0x30 ||
      bytes[1] !== bytes.length - 2) throw new Error("Invalid signature");
  let at = 2;
  const out = new Uint8Array(64);
  for (let part = 0; part < 2; part++) {
    if (bytes[at++] !== 2) throw new Error("Invalid signature");
    let length = bytes[at++];
    if (length < 1 || length > 33 || at + length > bytes.length ||
        (bytes[at] & 0x80) ||
        (length > 1 && bytes[at] === 0 && !(bytes[at + 1] & 0x80))) throw new Error("Invalid signature");
    if (length === 33) {
      if (bytes[at++] !== 0) throw new Error("Invalid signature");
      length--;
    }
    out.set(bytes.subarray(at, at + length), part * 32 + 32 - length);
    at += length;
  }
  if (at !== bytes.length) throw new Error("Invalid signature");
  return out;
}

async function checkContext(response, authData, type, challenge, domain, origin) {
  if (response.clientDataJSON.byteLength > 4096 || authData.length < 37 || authData.length > 8192) throw new Error("Invalid response");
  const client = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(response.clientDataJSON));
  if (client.type !== type || client.challenge !== challenge || client.origin !== origin ||
      (client.crossOrigin !== undefined && client.crossOrigin !== false) ||
      client.topOrigin !== undefined) throw new Error("Wrong ceremony context");
  const rpHash = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(domain)));
  if (!equal(authData.subarray(0, 32), rpHash) ||
      (authData[32] & 5) !== 5 ||
      ((authData[32] & 0x10) && !(authData[32] & 8))) throw new Error("Unverified credential");
}

export function checkBinding(binding, domain) {
  if (!binding || binding.version !== 1 || binding.domain !== domain ||
      Object.keys(binding).sort().join(",") !== "credentialId,domain,input,publicKeySpki,userId,version") throw new Error("Invalid probe binding");
  const id = decode(binding.credentialId);
  const spki = decode(binding.publicKeySpki);
  decode(binding.userId, 32); decode(binding.input, 32);
  if (id.length < 1 || id.length > 1024 || spki.length < 1 || spki.length > 1024) throw new Error("Invalid probe binding");
  return binding;
}

export async function createBinding(request, origin, credentials, signal, record) {
  const credential = await credentials.create({
    signal,
    publicKey: {
      rp: {id: request.domain, name: "Keypass development probe"},
      user: {id: decode(request.userId, 32), name: "Keypass development probe", displayName: "Keypass development probe"},
      challenge: decode(request.registrationChallenge, 32),
      pubKeyCredParams: [{type: "public-key", alg: -7}],
      authenticatorSelection: {residentKey: "required", userVerification: "required"},
      attestation: "none", timeout: 120000,
      extensions: {prf: {}},
    },
  });
  if (!credential || credential.type !== "public-key" || credential.rawId.byteLength > 1024) throw new Error("Invalid credential");
  const response = credential.response;
  const auth = new Uint8Array(response.getAuthenticatorData());
  await checkContext(response, auth, "webauthn.create", request.registrationChallenge, request.domain, origin);
  if (!(auth[32] & 0x40) || response.getPublicKeyAlgorithm() !== -7 ||
      credential.getClientExtensionResults().prf?.enabled !== true) throw new Error("PRF unavailable");
  const spki = response.getPublicKey();
  if (!spki) throw new Error("Missing public key");
  if (record) {
    if (!(response.attestationObject instanceof ArrayBuffer) || response.attestationObject.byteLength > 16384) throw new Error("Invalid response");
    record({credentialId: encode(new Uint8Array(credential.rawId)),
      clientDataJSON: encode(new Uint8Array(response.clientDataJSON)),
      attestationObject: encode(new Uint8Array(response.attestationObject)), prfEnabled: true});
  }
  // Browser checks are defense in depth; the evidence path is also verified in Dart.
  await crypto.subtle.importKey("spki", spki, {name: "ECDSA", namedCurve: "P-256"}, false, ["verify"]);
  return checkBinding({
    version: 1, domain: request.domain,
    credentialId: encode(new Uint8Array(credential.rawId)),
    userId: request.userId, publicKeySpki: encode(new Uint8Array(spki)),
    input: request.input,
  }, request.domain);
}

export async function evaluate(binding, challenge, origin, credentials, signal, record) {
  checkBinding(binding, binding.domain);
  const credential = await credentials.get({
    signal,
    publicKey: {
      rpId: binding.domain, challenge: decode(challenge, 32),
      allowCredentials: [{type: "public-key", id: decode(binding.credentialId)}],
      userVerification: "required", timeout: 120000,
      extensions: {prf: {eval: {first: decode(binding.input, 32)}}},
    },
  });
  if (!credential) throw new Error("Missing credential");
  // PRF output is trusted browser/provider output; the assertion signature does
  // not independently authenticate this client extension's bytes.
  const source = credential.getClientExtensionResults().prf?.results?.first;
  const secret = source instanceof ArrayBuffer ? new Uint8Array(source) : null;
  let transferred = false;
  try {
    if (credential.type !== "public-key" ||
        !equal(new Uint8Array(credential.rawId), decode(binding.credentialId))) throw new Error("Wrong credential");
    const response = credential.response;
    if (response.userHandle !== null && !equal(new Uint8Array(response.userHandle), decode(binding.userId))) throw new Error("Wrong user handle");
    const auth = new Uint8Array(response.authenticatorData);
    await checkContext(response, auth, "webauthn.get", challenge, binding.domain, origin);
    if (auth[32] & 0x40) throw new Error("Unexpected attested data");
    const key = await crypto.subtle.importKey("spki", decode(binding.publicKeySpki),
      {name: "ECDSA", namedCurve: "P-256"}, false, ["verify"]);
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", response.clientDataJSON));
    if (!await crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, key,
        es256Signature(new Uint8Array(response.signature)), join(auth, hash))) throw new Error("Bad signature");
    if (!secret || secret.length !== 32) throw new Error("PRF unavailable");
    record?.({credentialId: encode(new Uint8Array(credential.rawId)),
      clientDataJSON: encode(new Uint8Array(response.clientDataJSON)),
      authenticatorData: encode(auth), signature: encode(new Uint8Array(response.signature)),
      userHandle: response.userHandle === null ? null : encode(new Uint8Array(response.userHandle))});
    transferred = true;
    return secret;
  } finally {
    if (!transferred) secret?.fill(0);
  }
}

export async function runProbe(request, origin, credentials, gesture, signal) {
  if (!request || request.version !== 1 || typeof request.domain !== "string" ||
      !Array.isArray(request.challenges) || request.challenges.length !== 2 ||
      request.challenges[0] === request.challenges[1]) throw new Error("Invalid request");
  request.challenges.forEach(c => decode(c, 32));
  const withEvidence = request.evidenceVersion === 1;
  let registration = null;
  const assertions = [];
  let binding = request.binding ? checkBinding(request.binding, request.domain) : null;
  if (!binding) binding = await gesture("Create test passkey",
    () => createBinding(request, origin, credentials, signal, withEvidence ? value => { registration = value; } : undefined));
  let first, second;
  try {
    first = await gesture("Verify passkey · 1 of 2",
      () => evaluate(binding, request.challenges[0], origin, credentials, signal, withEvidence ? value => assertions.push(value) : undefined));
    second = await gesture("Verify passkey · 2 of 2",
      () => evaluate(binding, request.challenges[1], origin, credentials, signal, withEvidence ? value => assertions.push(value) : undefined));
    if (!equal(first, second)) throw new Error("Inconsistent PRF output");
    const metadata = utf8.encode(JSON.stringify(withEvidence ? {version: 1, binding, registration, assertions} : binding));
    const result = new Uint8Array(33 + metadata.length);
    result[0] = 1;
    result.set(first, 1);
    result.set(metadata, 33);
    return result;
  } finally { first?.fill(0); second?.fill(0); }
}
