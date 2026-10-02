# Backend contract

`lib/keypass_backend.dart` is an unstable adapter interface. Applications normally
import only `keypass.dart`. A backend is a trusted security component: returning
a `PasskeyAssertion` asserts that it has completed ceremony verification. The
core checks length, allowed credential membership, request metadata and
repeatability. An [internal Dart verifier](webauthn-verifier.md) now implements a
bounded ES256/none profile and is used by the browser probe and the shared native
backend. Experimental binding encoding v2 persists backup flags and signature
counters. Enrollment chains the state through both evaluations; unlock returns
the updated opaque record so the consumer can commit it. v1 bindings
are rejected rather than silently resetting verification state.

The native adapters are connected for development when their native host library
is linked. Production qualification still requires real-provider native-host
proof, packaged Dart consumers, and the device tests in the implementation plan. The recording backend in tests
intentionally uses invalid dummy COSE material and is not exported by the package.

## Responsibilities

The Dart core owns fresh 32-byte challenges and enrollment user handles,
a random original PRF input, immutable request snapshots, RP/route checks, one
active operation per isolate, cancellation/draining and owned result buffers. Registration is
followed by two assertions with different challenges and the same PRF input.
A result is returned only after the outputs match and operation cleanup succeeds. No PRF-derived bytes are
persisted or transformed into an encryption key by this layer.

The backend owns native SDK requests, main-thread dispatch, current presentation
context, native request lifetime, deadlines, exactly-once completion, raw
response parsing, ceremony verification and native memory cleanup. It must:

1. Require discoverable credentials at enrollment and user verification for
   registration and every evaluation. Generate no remote account as a side
   effect. The label is presentation data; the user handle is an opaque local ID.
2. Validate bounded response structures, ceremony type, challenge, expected
   RP ID hash and applicable app/origin identity. Validate credential ID, user
   handle where returned, UP/UV flags and the credential public key. Reject
   unsupported algorithms or malformed keys rather than guessing.
3. Verify assertion signatures over the correct authenticator data and client
   data hash using the enrolled key. Apply explicit backup/counter semantics for
   synced passkeys; zero counters alone are not a cloning failure. Use reviewed
   native or Dart cryptographic implementations, with independent test vectors.
4. Establish PRF support and require a 32-byte first output. A successful sign-in
   without PRF is `prfUnavailable`. Treat provider extension output as data from
   the trusted OS/client path, not as arbitrary caller-supplied assertion JSON.
5. For multiple bindings, attach each original PRF input to exactly its allowed
   credential. Return the credential actually selected. Report
   `selectionUnsupported` before UI if this cannot be honored in one ceremony.
6. Accept original WebAuthn PRF input bytes. The direct CTAP adapter must
   apply the WebAuthn-to-hmac-secret salt transformation exactly once and retain
   UV semantics. A native WebAuthn API performs its own normalization.

The [WebAuthn PRF specification](https://www.w3.org/TR/webauthn-3/#prf-extension)
defines the input/output semantics. Follow its registration and authentication
verification algorithms in addition to the PRF extension requirements.

## Lifetime and cancellation

`PasskeyAssertion.secret` transfers an exclusively owned writable buffer to the
core. Every evaluation must return a distinct allocation, even for equal bytes.
The backend must clear its own intermediate/native copies on all completion
paths. It must not keep a reference to the transferred buffer. FFI/JNI bridges
should use owned binary buffers and explicit release; no base64 secret strings
in the Dart-facing ABI. Android's SDK JSON should be parsed promptly and never
logged; complete erasure of immutable SDK strings cannot be promised.

Observe cancellation and inspect `isCancelled` before starting a request;
remove subscriptions when it completes. Cancel the native operation and settle
its future exactly once. Clear late results. Provider requests need bounded
deadlines so disposal can eventually drain. Do not free callback state until
late native completions can no longer access it.

The core rejects concurrent operations across clients in one isolate with `busy`. Native UI
coordination must also cover multiple clients/isolates sharing one host. No
speculative retries, hidden windows, or automatic browser launches.

Each public call obtains a fresh backend from its factory and disposes it exactly
once, including readiness checks and failures. A returned result holds no native
ceremony gate or selected connection. The native library itself remains loaded.

Cancellation before successful result transfer clears prospective secret output
and fails, including cancellation during backend cleanup. After transfer, the
caller owns the result and must call synchronous, idempotent
`PasskeyResult.dispose()`. Later cancellation cannot revoke it. Read-only borrowed
views observe zeroed storage after disposal; caller copies and derived keys are
outside that lifetime. Records remain readable after result disposal.

Do not abandon an operation Future or use Future.timeout as cancellation:
cancel its token and await settlement, disposing any successful result. Native
failure/cancellation may leave an OS request fenced busy until its framework
callback arrives. Application PIN/selection Futures may finish late after their
prompt cancellation signal; they are fenced, and late PIN buffers are cleared.
See [native ownership](../native/OWNERSHIP.md) for the exact per-platform boundary.

## Configuration, capabilities and failures

`Keypass.system(rpId:)` selects the linked native OS-provider backend.
`Keypass.hardware(rpId:, requestPin:, selectConnection:, onEvent:)` explicitly selects direct physical-key
access, currently libfido2 USB on macOS/Linux. Native provider bootstrap supplies
the current app window/Activity; hardware consumers supply local PIN/touch/key
selection UI. Neither constructor silently falls back to the other route.
Desktop CLIs use hardware keys; the historical browser probe remains outside
this interface and browser delivery is deferred.
The operation resolves the linked native ABI, validates its version, then checks
the actual presentation host. Missing libraries stay unavailable. No OS-name
check alone is a supported-provider claim.

Availability is prompt-free and describes whether a request can be attempted,
not whether every installed provider supports PRF. Real enrollment proves the
selected credential works. Do not enumerate credentials or promise offline
access from a capability probe.

Use `PasskeyException` codes. Do not forward raw SDK messages, credential JSON,
secret bytes, tokens, URLs or user names. Preserve provider ambiguity: if the API
conflates cancellation and missing credentials, do not invent a more specific
diagnosis. Unknown native exceptions become `backendFailure` at the core boundary.

Creation is not transactional across the OS provider and app storage. A failure
after registration may leave an orphan credential. The application must commit
its new unlock route only after create() succeeds and an atomic storage write commits. Universal provider deletion and automatic rollback are not
promised. Recovery from orphan creation is part of native qualification.


## Native ABI v1

The [C header](../native/include/keypass.h) defines start/poll/cancel/free. Public
request and evidence fields use bounded JSON; secret output is a separate 32-byte
binary tail. Poll transfers a native allocation which Dart copies and frees in a
`finally` block, including malformed/error/cancelled responses. Native frees wipe
the allocation. No callback pointer can outlive a Dart isolate. Requests have a
120-second provider timeout, Dart cancels after 125 seconds, and a broken native
ABI is bounded at 130 seconds. Native libraries remain loaded for process lifetime.

Apple expects the RP's HTTPS origin. Android derives the exact APK certificate
origin from PackageManager, independently of response data. Windows constructs
client data locally and delegates PRF normalization to WebAuthn. All three pass
raw registration/assertion evidence through the same verifier before secret access.


## Direct hardware contract

The [hardware adapter](../native/hardware/README.md) has a separate ABI v1 in
`native/hardware/keypass_hardware.h`. Public requests/evidence use bounded JSON;
PIN input and PRF output use binary buffers. Poll can return a nonterminal
interaction event before the terminal success/error frame. Only one native
operation may be active across clients/isolates, and the slot remains occupied
until the terminal response has been drained. Cancellation discards late secrets.

The local client-data hash is SHA-256 over `UTF8("Keypass direct CTAP v1")`,
a zero byte, operation byte (1 registration / 2 assertion), UTF-8 namespace,
another zero byte, and the fresh 32-byte core challenge. It is a local ceremony
context, not WebAuthn client JSON or proof of a requesting website/executable.

libfido2 verifies registration attestation signatures. The hardware Dart profile
then requires RP/credential identity, ES256, UP/UV, `hmac-secret=true`, and
`credProtect=3`; assertions must also carry a correctly signed hmac-secret
extension and satisfy binding/counter checks. Native CTAP handles the encrypted
extension channel and returns the corresponding decrypted 32-byte output.
No manufacturer certificate-chain trust is claimed.

Provider bindings retain exact v2 serialization. Hardware bindings use v3 with
`route=hardware`, `verification=required`, transport hints, and the existing
original-input `webauthn-prf-v1` semantics. Route mismatch is rejected before
availability/prompt calls. An advertised NFC hint does not imply implemented
NFC transport. The current hardware backend supports one binding per ceremony.

Selection callbacks have a 120-second deadline and a cancellation signal.
Native operations have a 120-second deadline, Dart cancels at 125 seconds,
and an unresponsive ABI is bounded at 135 seconds plus a final 10-second drain.
PIN callbacks return owned writable PIN bytes, never persistent strings; malformed
or non-writable input is rejected before submission. One rejected PIN produces
one typed error, with no automatic retry, setup, change, reset or deletion.
