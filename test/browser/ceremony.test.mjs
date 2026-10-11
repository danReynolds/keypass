import test from "node:test";
import assert from "node:assert/strict";
import {encode, makePeer, makeChannel, transcript} from "../../tool/browser/protocol.mjs";
import {runProbe} from "../../tool/browser/ceremony.mjs";
import {fakeCredentials} from "./fake_credentials.mjs";
const origin = "https://vault.example.com";
const request = () => ({
  version: 2, domain: "vault.example.com",
  userId: encode(crypto.getRandomValues(new Uint8Array(32))),
  input: encode(crypto.getRandomValues(new Uint8Array(32))),
  registrationChallenge: encode(crypto.getRandomValues(new Uint8Array(32))),
  challenges: [0, 1].map(() => encode(crypto.getRandomValues(new Uint8Array(32)))),
});
const gesture = (_, action) => action();
test("signed ES256 assertions yield equal PRF and clear provider buffers", async () => {
  const credentials = await fakeCredentials(origin);
  const result = await runProbe(request(), credentials, gesture);
  assert.equal(result[0], 1);
  assert(result.subarray(1, 33).every(b => b === 42));
  assert(credentials.outputs.every(b => b.every(v => v === 0)));
  result.fill(0);
});
const changes = {
  "wrong credential": c => { c.rawId = new Uint8Array(32).buffer; },
  "inconsistent PRF": (_, ext, count) => {
    if (count === 2) new Uint8Array(ext.prf.results.first)[0] ^= 1;
  },
};
for (const [name, mutate] of Object.entries(changes)) {
  test("rejects " + name + " and clears PRF buffers", async () => {
    const credentials = await fakeCredentials(origin, mutate);
    await assert.rejects(runProbe(request(), credentials, gesture));
    assert(credentials.outputs.every(b => b.every(v => v === 0)));
  });
}
test("missing PRF fails rather than accepting successful authentication", async () => {
  const credentials = await fakeCredentials(origin, (_, ext) => { delete ext.prf; });
  await assert.rejects(runProbe(request(), credentials, gesture), /PRF unavailable/);
  credentials.outputs.forEach(b => b.fill(0));
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
  const initialRequest = request();
  const initial = await runProbe(initialRequest, credentials, gesture);
  const binding = credentials.binding(initialRequest.input);
  const expected = initial.slice(1, 33);
  initial.fill(0);
  credentials.create = () => assert.fail("Must not enroll on a saved-binding path");
  const reused = await runProbe({...request(), binding, userId: binding.userId, input: binding.input}, credentials, gesture);
  assert.deepEqual(reused.subarray(1, 33), expected);
  assert.equal(JSON.parse(new TextDecoder().decode(reused.subarray(33))).registration, null);
  assert.equal(credentials.outputs.length, 4);
  assert(credentials.outputs.every(b => b.every(v => v === 0)));
  reused.fill(0); expected.fill(0);
});

test("evidence includes public raw registration and assertions without another PRF copy", async () => {
  const credentials = await fakeCredentials(origin);
  const initialRequest = request();
  const result = await runProbe(initialRequest,credentials,gesture);
  const evidence = JSON.parse(new TextDecoder().decode(result.subarray(33)));
  assert.deepEqual(Object.keys(evidence).sort(),["assertions","registration","version"]);
  assert.equal(evidence.version,2);
  assert.equal(evidence.registration.prfEnabled,true);
  assert(evidence.registration.attestationObject.length>0);
  assert.equal(evidence.assertions.length,2);
  assert.deepEqual(Object.keys(evidence.assertions[0]).sort(),["authenticatorData","clientDataJSON","credentialId","signature","userHandle"]);
  credentials.create = () => assert.fail("Saved binding must not be re-enrolled");
  const binding = credentials.binding(initialRequest.input);
  const reused = await runProbe({...request(),binding,userId:binding.userId,input:binding.input},credentials,gesture);
  const reuseEvidence = JSON.parse(new TextDecoder().decode(reused.subarray(33)));
  assert.equal(reuseEvidence.registration,null);
  assert(credentials.outputs.every(b=>b.every(v=>v===0)));
  result.fill(0); reused.fill(0);
});
