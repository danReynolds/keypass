import test from "node:test";
import assert from "node:assert/strict";
import {encode, makePeer, makeChannel, transcript} from "../../tool/browser/protocol.mjs";
import {runProbe, es256Signature} from "../../tool/browser/ceremony.mjs";
import {fakeCredentials} from "./fake_credentials.mjs";
const origin = "https://vault.example.com";
const request = () => ({
  version: 1, domain: "vault.example.com",
  userId: encode(crypto.getRandomValues(new Uint8Array(32))),
  input: encode(crypto.getRandomValues(new Uint8Array(32))),
  registrationChallenge: encode(crypto.getRandomValues(new Uint8Array(32))),
  challenges: [0, 1].map(() => encode(crypto.getRandomValues(new Uint8Array(32)))),
});
const gesture = (_, action) => action();
test("signed ES256 assertions yield equal PRF and clear provider buffers", async () => {
  const credentials = await fakeCredentials(origin);
  const result = await runProbe(request(), origin, credentials, gesture);
  assert.equal(result[0], 1);
  assert(result.subarray(1, 33).every(b => b === 42));
  assert(credentials.outputs.every(b => b.every(v => v === 0)));
  result.fill(0);
});
const changes = {
  "bad signature": c => { new Uint8Array(c.response.signature)[10] ^= 1; },
  "missing UV": c => { new Uint8Array(c.response.authenticatorData)[32] = 1; },
  "wrong RP hash": c => { new Uint8Array(c.response.authenticatorData)[0] ^= 1; },
  "wrong user handle": c => { c.response.userHandle = new Uint8Array(32).buffer; },
  "wrong credential": c => { c.rawId = new Uint8Array(32).buffer; },
  "wrong challenge": c => {
    const client = JSON.parse(new TextDecoder().decode(c.response.clientDataJSON));
    client.challenge = encode(new Uint8Array(32));
    c.response.clientDataJSON = new TextEncoder().encode(JSON.stringify(client)).buffer;
  },
  "cross origin": c => {
    const client = JSON.parse(new TextDecoder().decode(c.response.clientDataJSON));
    client.crossOrigin = true;
    c.response.clientDataJSON = new TextEncoder().encode(JSON.stringify(client)).buffer;
  },
  "inconsistent PRF": (_, ext, count) => {
    if (count === 2) new Uint8Array(ext.prf.results.first)[0] ^= 1;
  },
};
for (const [name, mutate] of Object.entries(changes)) {
  test("rejects " + name + " and clears PRF buffers", async () => {
    const credentials = await fakeCredentials(origin, mutate);
    await assert.rejects(runProbe(request(), origin, credentials, gesture));
    assert(credentials.outputs.every(b => b.every(v => v === 0)));
  });
}
test("missing PRF fails rather than accepting successful authentication", async () => {
  const credentials = await fakeCredentials(origin, (_, ext) => { delete ext.prf; });
  await assert.rejects(runProbe(request(), origin, credentials, gesture), /PRF unavailable/);
  credentials.outputs.forEach(b => b.fill(0));
});
test("strict DER rejects malleable/malformed encodings", () => {
  for (const bytes of [
    [], [48, 6, 2, 1, 128, 2, 1, 1],
    [48, 7, 2, 2, 0, 1, 2, 1, 1],
    [48, 6, 2, 0, 2, 2, 1, 1],
    [48, 6, 2, 1, 1, 2, 1],
  ]) assert.throws(() => es256Signature(new Uint8Array(bytes)));
});
test("channel binds origin, RP, session and direction", async () => {
  const server = await makePeer(), browser = await makePeer();
  const context = transcript(origin, "vault.example.com", "session", server.publicKey, browser.publicKey);
  const a = await makeChannel(server, browser.publicKey, context, true);
  const b = await makeChannel(browser, server.publicKey, context);
  assert.equal(a.code, b.code);
  const frame = await a.seal(new Uint8Array([7, 8]));
  await assert.rejects(a.open(frame));
  for (const bad of [
    context.replace(origin, "https://other.example.com"),
    context.replace('"vault.example.com"', '"other.example.com"'),
    context.replace('"session"', '"other-session"'),
  ]) {
    const impostor = await makeChannel(browser, server.publicKey, bad);
    assert.notEqual(impostor.code, a.code);
    await assert.rejects(impostor.open(frame));
    impostor.close();
  }
  assert.deepEqual(await b.open(frame), new Uint8Array([7, 8]));
  await assert.rejects(b.open(frame));
  a.close(); b.close();
  await assert.rejects(a.seal(new Uint8Array([1])));
});

test("saved binding reuses the credential without any replacement enrollment", async () => {
  const credentials = await fakeCredentials(origin);
  const initial = await runProbe(request(), origin, credentials, gesture);
  const binding = JSON.parse(new TextDecoder().decode(initial.subarray(33)));
  const expected = initial.slice(1, 33);
  initial.fill(0);
  credentials.create = () => assert.fail("Must not enroll on a saved-binding path");
  const reused = await runProbe({...request(), binding}, origin, credentials, gesture);
  assert.deepEqual(reused.subarray(1, 33), expected);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(reused.subarray(33))), binding);
  assert.equal(credentials.outputs.length, 4);
  assert(credentials.outputs.every(b => b.every(v => v === 0)));
  reused.fill(0); expected.fill(0);
});

test("evidence includes public raw registration and assertions without another PRF copy", async () => {
  const credentials = await fakeCredentials(origin);
  const result = await runProbe({...request(),evidenceVersion:1},origin,credentials,gesture);
  const evidence = JSON.parse(new TextDecoder().decode(result.subarray(33)));
  assert.deepEqual(Object.keys(evidence).sort(),["assertions","binding","registration","version"]);
  assert.equal(evidence.version,1);
  assert.equal(evidence.registration.prfEnabled,true);
  assert(evidence.registration.attestationObject.length>0);
  assert.equal(evidence.assertions.length,2);
  assert.deepEqual(Object.keys(evidence.assertions[0]).sort(),["authenticatorData","clientDataJSON","credentialId","signature","userHandle"]);
  credentials.create = () => assert.fail("Saved binding must not be re-enrolled");
  const reused = await runProbe({...request(),binding:evidence.binding,evidenceVersion:1},origin,credentials,gesture);
  const reuseEvidence = JSON.parse(new TextDecoder().decode(reused.subarray(33)));
  assert.equal(reuseEvidence.registration,null);
  assert.deepEqual(reuseEvidence.binding,evidence.binding);
  assert(credentials.outputs.every(b=>b.every(v=>v===0)));
  result.fill(0); reused.fill(0);
});
