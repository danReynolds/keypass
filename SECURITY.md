# Keypass security

Keypass returns credential-bound material for an application's encryption scheme.
It does not provide a vault or recovery service. No independent human security
audit has been completed. See the [review guide](doc/external-review.md) for scope
and evidence.

## Contract

`create` registers a credential and verifies two matching 32-byte PRF outputs
with fresh challenges. `unlock` uses the saved credential, original PRF input
and verification state. Evaluations require user presence and verification;
ordinary sign-in without PRF fails. No operation silently enrolls a replacement
or switches routes.

Built-in backends validate bounded evidence, RP/challenge/credential binding,
public keys, signatures, UP/UV flags and counter/backup state. Hardware requires
`hmac-secret`, enrollment `credProtect=3` and non-backup-eligible credentials.
Unsupported profiles fail. See the [verifier specification](doc/webauthn-verifier.md).

## Trust boundaries

- **Providers and native code are trusted.** WebAuthn signatures do not
  independently authenticate system-provider PRF extension bytes. Repeatability
  does not prove that a malicious provider supplied secure material.
- **Identity depends on the route.** Apple/Android use app/domain associations.
  Windows constructs its origin from the caller's RP ID; it does not prove
  website control or executable identity. Direct CTAP namespaces likewise do
  not identify the caller; the key still enforces its credential, PIN/on-key
  verification and presence requirements.
- **Attestation is not provenance.** Signature checks do not establish a
  manufacturer chain or qualify every device advertising the required features.
- **Custom backends are trusted.** `keypass_backend.dart` is unstable adapter
  infrastructure; the core does not independently verify arbitrary backend assertions.
- **Build dependencies are trusted.** Record native library versions/hashes and
  retain notices. [Hooks](doc/build-hooks.md) verify a pinned downloaded header;
  consumers still own toolchains, native libraries, signing and permissions.

## Consumer responsibilities

Use a purpose-bound KDF and authenticated encryption. Authenticate saved method
metadata, decrypt the original envelope, and atomically commit updated verifier
state before exposing a session. Derive from stable identity/context, not mutable
counters. Record decoding validates structure, not authenticity. Records contain
identifiers; keep them out of public logs despite being nonsecret.

Provide your own transaction, concurrency, backup and recovery policy. Losing
records or all usable credentials can make data unrecoverable. Provider sync does
not guarantee cross-device PRF continuity. Removing a method does not delete its
provider credential or revoke old snapshots. Keypass provides no rollback protection.

Dispose results in `finally`; clear caller-owned PINs, derived keys and plaintext.
Cancel through `PasskeyCancellation`, await settlement and dispose late successful
results. Keep secret/transport tracing disabled. Wiping covers owned mutable
buffers, not every Dart VM, provider or immutable-string copy. A provider that
never acknowledges cancellation may remain busy until process restart.
See [native ownership](native/OWNERSHIP.md).

## Limits

Use patched OS/provider versions. A compromised host process, OS, provider or
keylogger is outside the threat model. Compile/synthetic-test success is not
physical-device proof. Android OS-provider, Windows runtime and wider hardware,
sync/offline and lifecycle coverage remain incomplete; the
[platform guide](doc/platforms.md) links the exact evidence.

## Reporting

Email **me@danreynolds.ca** privately with the affected revision, platform/provider,
impact and a disposable-data reproduction. Do not post undisclosed bugs publicly
or include real PINs, secrets, credential records or vault contents.
