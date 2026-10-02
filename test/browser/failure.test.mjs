import test from "node:test";
import assert from "node:assert/strict";
import {describeFailure} from "../../tool/browser/failure.mjs";

test("untrusted provider diagnostics never become user-facing text", () => {
  const secret = "PRIVATE-CREDENTIAL-AND-PRF-123";
  for (const error of [
    new Error(secret), {name: secret, message: secret},
    {name: "NotAllowedError", message: secret}, null,
  ]) assert(!JSON.stringify(describeFailure(error)).includes(secret));
});
test("ambiguous provider refusal is not reported as definite cancellation", () => {
  const failure = describeFailure({name: "NotAllowedError"});
  assert.equal(failure.code, "notAllowed");
  assert.match(failure.message, /cancelled, timed out, or was not allowed/);
});
test("PRF failure is distinct from successful authentication or signature failure", () => {
  assert.equal(describeFailure(new Error("PRF unavailable")).code, "prfUnavailable");
  assert.equal(describeFailure(new Error("Bad signature")).code, "verificationFailed");
});
