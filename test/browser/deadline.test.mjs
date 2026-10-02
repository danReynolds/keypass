import test from "node:test";
import assert from "node:assert/strict";
import {watchDeadline} from "../../tool/browser/deadline.mjs";
import {requestGesture} from "../../tool/browser/gesture.mjs";

test("an expired encrypted request never starts a provider operation", async () => {
  const controller = new AbortController(), button = {};
  watchDeadline(99, controller, {now: () => 100});
  await assert.rejects(requestGesture(button, "Create", controller.signal, () => assert.fail()), /Session expired/);
  assert.equal(button.disabled, true);
});
test("session expiry disables an idle create button and erases late provider output", async () => {
  for (const active of [false, true]) {
    let fire, complete;
    const controller = new AbortController(), button = {};
    watchDeadline(500, controller, {now: () => 100, set: (f, delay) => {
      assert.equal(delay, 400); fire = f; return 1;
    }, clear: () => {}});
    const pending = requestGesture(button, "Create", controller.signal, () => {
      assert(active); return new Promise(resolve => { complete = resolve; });
    });
    if (active) button.onclick();
    const rejection = assert.rejects(pending, /Session expired/);
    fire();
    await rejection;
    assert.equal(button.disabled, true);
    if (active) {
      const secret = new Uint8Array(32).fill(42);
      complete(secret);
      await new Promise(resolve => setImmediate(resolve));
      assert(secret.every(v => v === 0));
    }
  }
});
test("bad or excessive deadlines fail closed; successful completion cancels timer", () => {
  for (const deadline of [undefined, NaN, Infinity, 700001, "500"]) {
    const controller = new AbortController();
    watchDeadline(deadline, controller, {now: () => 100});
    assert(controller.signal.aborted);
  }
  const controller = new AbortController();
  let cleared = false;
  const stop = watchDeadline(200, controller, {
    now: () => 100, set: () => 123,
    clear: id => { assert.equal(id, 123); cleared = true; },
  });
  stop(); assert(cleared); assert(!controller.signal.aborted);
});
