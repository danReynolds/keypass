import test from "node:test";
import assert from "node:assert/strict";
import {requestGesture} from "../../tool/browser/gesture.mjs";

test("provider starts only on click and exactly once with user activation", async () => {
  const button = {}, controller = new AbortController();
  let calls = 0, insideClick = false;
  const pending = requestGesture(button, "Verify", controller.signal, () => {
    assert(insideClick); calls++; return "public result";
  });
  assert.equal(calls, 0);
  const click = button.onclick;
  insideClick = true; click(); click(); insideClick = false;
  assert.equal(await pending, "public result");
  assert.equal(calls, 1);
  assert.equal(button.onclick, null);
  assert.equal(button.disabled, true);
});
test("cancel before click never invokes provider", async () => {
  const button = {}, controller = new AbortController();
  const pending = requestGesture(button, "Verify", controller.signal, () => assert.fail());
  const rejection = assert.rejects(pending, {name: "AbortError"});
  controller.abort();
  await rejection;
  assert.equal(button.onclick, null);
});
test("cancel during provider work erases a late secret instead of losing ownership", async () => {
  const button = {}, controller = new AbortController();
  let complete;
  const pending = requestGesture(button, "Verify", controller.signal,
    () => new Promise(resolve => { complete = resolve; }));
  button.onclick();
  const rejection = assert.rejects(pending, {name: "AbortError"});
  controller.abort();
  await rejection;
  const secret = new Uint8Array(32).fill(42);
  complete(secret);
  await new Promise(resolve => setImmediate(resolve));
  assert(secret.every(v => v === 0));
});
test("pre-cancelled request has no active button", async () => {
  const button = {}, controller = new AbortController();
  controller.abort();
  await assert.rejects(requestGesture(button, "Verify", controller.signal,
    () => assert.fail()), {name: "AbortError"});
  assert.equal(button.disabled, true);
});
test("synchronous and asynchronous provider errors retain their identity", async () => {
  for (const async of [false, true]) {
    const button = {}, controller = new AbortController();
    const error = new Error("private diagnostic");
    const pending = requestGesture(button, "Verify", controller.signal, () => {
      if (async) return Promise.reject(error);
      throw error;
    });
    const rejection = assert.rejects(pending, actual => actual === error);
    button.onclick();
    await rejection;
    assert.equal(button.onclick, null);
  }
});
