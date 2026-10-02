// Node WebCrypto peer for cross-language/HTTP tests. Synthetic passkey only.
import assert from "node:assert/strict";
import {decode, makePeer, makeChannel, transcript} from "../../tool/browser/protocol.mjs";
import {runProbe} from "../../tool/browser/ceremony.mjs";
import {fakeCredentials} from "./fake_credentials.mjs";
const args = JSON.parse(process.argv[2]);
const remote = decode(args.key, 32);
const peer = await makePeer();
const channel = await makeChannel(peer, remote,
  transcript(args.origin, args.domain, args.session, remote, peer.publicKey));
async function post(path, body, origin = args.origin) {
  return fetch(args.endpoint + "/" + path, {method: "POST",
    headers: {Origin: origin, "Content-Type": "application/octet-stream"}, body});
}
assert.equal((await post("hello", peer.publicKey, "https://evil.example")).status, 403);
assert.equal((await post("hello", peer.publicKey)).status, 204);
assert.equal((await post("hello", peer.publicKey)).status, 409);
process.stdout.write(JSON.stringify({code: channel.code}) + "\n");
const confirmation = await channel.seal(new Uint8Array([1]));
const requestResponse = await post("confirm", confirmation);
if (args.cancel) {
  assert.equal(requestResponse.status, 200);
  const response = await post("abort", await channel.seal(new Uint8Array([0])));
  assert.equal(response.status, 204);
  channel.close();
} else if (args.reject) {
  assert.equal(requestResponse.status, 400);
  channel.close();
} else {
  assert.equal(requestResponse.status, 200);
  const wire = new Uint8Array(await requestResponse.arrayBuffer());
  const clear = await channel.open(wire);
  const request = JSON.parse(new TextDecoder().decode(clear));
  clear.fill(0);
  assert(Number.isSafeInteger(request.expiresAt));
  assert(request.expiresAt > Date.now() && request.expiresAt <= Date.now() + 600000);
  await assert.rejects(channel.open(wire));
  const credentials = await fakeCredentials(args.origin);
  let result = await runProbe(request, args.origin, credentials, (_, action) => action());
  assert(credentials.outputs.every(b => b.every(v => v === 0)));
  if (args.corruptEvidence) {
    const metadata = JSON.parse(new TextDecoder().decode(result.subarray(33)));
    const sig = decode(metadata.assertions[0].signature); sig[sig.length-1] ^= 1;
    metadata.assertions[0].signature = Buffer.from(sig).toString("base64url");
    const changed = new Uint8Array([...result.subarray(0,33),...new TextEncoder().encode(JSON.stringify(metadata))]);
    result.fill(0); result = changed;
  }
  const frame = await channel.seal(result);
  if (args.tamper) frame[frame.length - 1] ^= 1;
  const response = await post("result", frame);
  assert.equal(response.status, args.tamper ? 400 : 204);
  result.fill(0); channel.close();
}
