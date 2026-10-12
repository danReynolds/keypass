# Keypass security

Keypass supplies credential-bound input key material to an application's
encryption scheme. It is a prerelease Dart SDK with native adapters. It does
not store a vault, provide account recovery, or operate an authentication service.
Start with the [external review guide](doc/external-review.md) for source and
dependency baselines, code locations and remaining qualification.

## Security contract

`create` registers a credential and verifies two matching 32-byte secret
evaluations using fresh challenges. `unlock` uses the saved credential, original
PRF input and verification state; it never registers a replacement or chooses a
weaker route. Every evaluation requires user presence and verification. A
provider login without the required PRF capability fails.

Built-in backends check bounded ceremony evidence: RP hash, challenge, credential
identity, supported public key and signatures, user presence/verification and
counter/backup state. System routes also check the configured app/origin context.
The direct hardware profile requires `hmac-secret`, `credProtect=3` at enrollment
and non-backup-eligible credentials. The
[verifier contract](doc/webauthn-verifier.md) defines the precise accepted profiles;
unsupported authenticators fail rather than relaxing requirements.

The SDK has no automatic system/hardware/browser fallback. Missing libraries,
presentation hosts or capabilities are errors. Browser code is a separate
research probe, not a public backend.

## Trust boundaries

- The OS, credential provider, native adapters and protocol dependencies are
  trusted. WebAuthn assertion signatures do not independently authenticate the
  system provider's PRF extension bytes. Repeatability is a check on the selected
  provider, not proof that a malicious provider supplied secure material.
- Apple/Android system routes use app/domain associations. The experimental
  Windows WebAuthn adapter has no equivalent association check: it constructs
  the client origin from the configured RP ID. Checking that origin's consistency
  does not authenticate the local executable or prove control of a website.
  Direct CTAP access likewise uses an RP namespace without authenticating the
  local executable. Another
  program can request that namespace; the key's credential, PIN/on-key
  verification and presence requirements still apply. Never treat an RP ID as
  a local application sandbox.
- Attestation signature checks do not establish manufacturer provenance. There
  is no vendor allowlist or certificate-chain hardware guarantee. A supported
  protocol capability is distinct from qualification of a particular device.
- The low-level `keypass_backend.dart` interface is trusted, unstable adapter
  infrastructure. Supplying a custom backend changes the trust boundary; the
  core alone does not verify arbitrary backend assertions.
- Build tools and bundled native libraries are part of the trusted supply chain.
  Desktop hooks download a checksum-pinned header and use installed native
  development libraries. Preserve dependency versions, notices and bundle
  integrity. Hooks do not grant OS permissions or perform signing/notarization.

## Consumer responsibilities

Use a purpose-bound KDF and authenticated encryption/key-wrapping scheme.
`PasskeyRecord` is nonsecret recovery metadata, but may contain credential and
user identifiers; do not publish or log it unnecessarily. Decoding validates
structure, not authenticity. Authenticate the entire saved method metadata,
decrypt the original envelope, and atomically persist advanced verification
state before returning a usable application session. Use stable context for
key derivation; mutable counters are not a stable wrapping-key identity.

Keypass does not provide storage transactions, rollback protection, backup,
synchronization or recovery. Losing the record or every usable credential can
make encrypted data unrecoverable. A synced passkey does not establish PRF
continuity on another device/provider. Removing a consumer's method record does
not delete the provider's credential or revoke old encrypted snapshots.

Dispose each `PasskeyResult` in `finally`, and clear your own PIN copies, derived
keys and plaintext. Await operations through cancellation and dispose late
successful results. Native tracing and secret logging must stay disabled.
Owned mutable buffers are cleared; Dart VM, provider SDK and immutable string
copies cannot be guaranteed erased. See [native ownership](native/OWNERSHIP.md).

A provider that never acknowledges cancellation may retain its process-local
busy guard until restart. That is an availability limitation; it must not permit
overlapping operations or publish a late secret into another request.

## Scope and evidence

Use maintained, security-patched OS/provider versions. Compilation, emulator
smoke tests, synthetic cryptographic vectors and a successful readiness probe
are different from physical credential qualification. The
[platform matrix](doc/platforms.md) and [dated receipts](doc/validation.md)
record the observed scope. Android OS-provider, Windows runtime, broader
hardware vendors/transports and failure/lifecycle coverage remain incomplete.

Keypass cannot defend against a compromised host process, root/kernel attacker,
malicious provider, keylogger or a consumer that discloses returned secrets.
Neither internal tests nor AI-assisted reviews constitute an independent human
cryptographic/security audit. No such completed audit is claimed.

## Reporting

Email **me@danreynolds.ca** privately with the affected version/source revision,
platform/provider, impact and a minimal reproduction using disposable data.
Do not include real PINs, secret outputs, credential records or vault contents.
Do not open a public issue for an undisclosed security bug. GitHub private
vulnerability reporting was not enabled for this repository when this guide was
prepared; use email rather than assuming a private advisory form is available.
