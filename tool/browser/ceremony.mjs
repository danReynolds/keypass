import {encode, decode} from "./protocol.mjs";

const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
function bytes(value, max) {
  if (!(value instanceof ArrayBuffer) || value.byteLength < 1 || value.byteLength > max) throw new Error("Invalid response");
  return new Uint8Array(value);
}

// This helper only collects evidence and PRF output. The paired Dart process
// verifies registration, signatures, origin, UV and persisted counter state
// with the same verifier as the native SDK before using any returned secret.
async function createBinding(request, credentials, signal, record) {
  const credential = await credentials.create({
    signal,
    publicKey: {
      rp: {id: request.domain, name: "Keypass development probe"},
      user: {id: decode(request.userId, 32), name: "Keypass development probe", displayName: "Keypass development probe"},
      challenge: decode(request.registrationChallenge, 32),
      pubKeyCredParams: [{type: "public-key", alg: -7}],
      authenticatorSelection: {residentKey: "required", userVerification: "required"},
      attestation: "none", timeout: 120000, extensions: {prf: {}},
    },
  });
  if (!credential || credential.type !== "public-key") throw new Error("Invalid credential");
  if (credential.getClientExtensionResults().prf?.enabled !== true) throw new Error("PRF unavailable");
  const credentialId = encode(bytes(credential.rawId, 1024));
  record({credentialId, clientDataJSON: encode(bytes(credential.response.clientDataJSON, 4096)),
    attestationObject: encode(bytes(credential.response.attestationObject, 16384)), prfEnabled: true});
  return {domain: request.domain, credentialId, userId: request.userId, input: request.input};
}

async function evaluate(binding, challenge, credentials, signal, record) {
  const credential = await credentials.get({signal, publicKey: {
    rpId: binding.domain, challenge: decode(challenge, 32),
    allowCredentials: [{type: "public-key", id: decode(binding.credentialId)}],
    userVerification: "required", timeout: 120000,
    extensions: {prf: {eval: {first: decode(binding.input, 32)}}},
  }});
  if (!credential) throw new Error("Missing credential");
  const source = credential.getClientExtensionResults().prf?.results?.first;
  const secret = source instanceof ArrayBuffer ? new Uint8Array(source) : null;
  let transferred = false;
  try {
    if (credential.type !== "public-key" ||
        !equal(bytes(credential.rawId, 1024), decode(binding.credentialId))) throw new Error("Wrong credential");
    if (!secret || secret.length !== 32) throw new Error("PRF unavailable");
    const response = credential.response;
    record({credentialId: encode(bytes(credential.rawId, 1024)),
      clientDataJSON: encode(bytes(response.clientDataJSON, 4096)),
      authenticatorData: encode(bytes(response.authenticatorData, 8192)),
      signature: encode(bytes(response.signature, 72)),
      userHandle: response.userHandle === null ? null : encode(bytes(response.userHandle, 64))});
    transferred = true;
    return secret;
  } finally { if (!transferred) secret?.fill(0); }
}

export async function runProbe(request, credentials, gesture, signal) {
  if (!request || request.version !== 2 || typeof request.domain !== "string" ||
      !Array.isArray(request.challenges) || request.challenges.length !== 2 ||
      request.challenges[0] === request.challenges[1]) throw new Error("Invalid request");
  request.challenges.forEach(c => decode(c, 32));
  let registration = null;
  const assertions = [];
  let binding = request.binding;
  if (binding) {
    if (binding.version !== 2 || binding.prf !== "webauthn-prf-v1" ||
        binding.domain !== request.domain || binding.userId !== request.userId ||
        binding.input !== request.input) throw new Error("Invalid binding");
  } else {
    binding = await gesture("Create test passkey",
      () => createBinding(request, credentials, signal, value => { registration = value; }));
  }
  let first, second;
  try {
    first = await gesture("Verify passkey · 1 of 2",
      () => evaluate(binding, request.challenges[0], credentials, signal, value => assertions.push(value)));
    second = await gesture("Verify passkey · 2 of 2",
      () => evaluate(binding, request.challenges[1], credentials, signal, value => assertions.push(value)));
    if (!equal(first, second)) throw new Error("Inconsistent PRF output");
    const metadata = new TextEncoder().encode(JSON.stringify({version: 2, registration, assertions}));
    const result = new Uint8Array(33 + metadata.length);
    result[0] = 1; result.set(first, 1); result.set(metadata, 33);
    return result;
  } finally { first?.fill(0); second?.fill(0); }
}
