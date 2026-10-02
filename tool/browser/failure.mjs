// Finite diagnostics only. Never display raw provider errors, JSON or secrets.
const local = new Map([
  ["Session expired", ["timeout", "This CLI session expired. Start a fresh probe before creating or using a passkey."]],
  ["PRF unavailable", ["prfUnavailable", "The selected credential did not provide the encryption-secret extension (PRF)."]],
  ["Inconsistent PRF output", ["inconsistentSecret", "The two encryption-secret results differed."]],
  ["Bad signature", ["verificationFailed", "The passkey assertion signature did not verify."]],
  ["Invalid signature", ["verificationFailed", "The passkey signature encoding was invalid."]],
  ["Wrong ceremony context", ["verificationFailed", "The returned challenge, origin or ceremony did not match."]],
  ["Unverified credential", ["verificationFailed", "The credential did not meet RP or user-verification requirements."]],
  ["Wrong credential", ["verificationFailed", "The provider returned a different credential."]],
  ["Wrong user handle", ["verificationFailed", "The provider returned a different user handle."]],
  ["Bridge rejected request", ["bridgeRejected", "The CLI rejected this browser session or operation."]],
  ["Unsupported context", ["browserUnsupported", "This page needs a secure, top-level browser with WebAuthn support."]],
  ["Cancelled", ["cancelled", "The test was cancelled."]],
]);
const provider = new Map([
  ["NotAllowedError", ["notAllowed", "The request was cancelled, timed out, or was not allowed. The browser does not distinguish these reliably."]],
  ["AbortError", ["cancelled", "The test was cancelled."]],
  ["NotSupportedError", ["browserUnsupported", "The browser or provider does not support a required feature."]],
  ["SecurityError", ["domainRejected", "The browser rejected the origin or relying-party identity."]],
  ["InvalidStateError", ["credentialState", "The provider could not use the requested credential state."]],
]);
export function describeFailure(error) {
  const [code, message] = provider.get(error?.name) ??
    local.get(error?.message) ?? ["probeFailed", "The browser test stopped. Check browser support and the CLI connection."];
  return {code, message};
}
