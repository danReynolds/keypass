# Dart WebAuthn verifier

`lib/src/webauthn/verifier.dart` implements an internal, bounded verification
profile. The browser probe sends public ceremony evidence across its paired
channel and the CLI verifies it before processing or persisting the separate
PRF result. Native Apple/Android/Windows adapters now use the same verifier
before exposing their separate binary PRF output. The public browser backend
remains unconnected.

## Supported profile

- ES256 with a P-256 EC2 COSE key. PointyCastle 4.0.0 supplies SHA-256 and ECDSA
  verification in Dart; there is no Flutter or Node runtime dependency.
- Enrollment uses `attestation: none`. The verifier parses the original CBOR
  attestation object, requires an empty statement with format `none`, and obtains
  the credential ID and COSE key from its authenticator data. It does not trust
  the browser's separately parsed SPKI key; the probe checks that they match.
- Exact configured origin and RP hash, fresh 32-byte challenge, expected ceremony
  type, required UP/UV flags, expected credential ID and returned user handle.
- Browser HTTPS origins and native app origins are checked explicitly. Android
  expects the installed signing-certificate origin obtained independently from
  PackageManager. Cross-origin frames, `topOrigin`, AppID and
  related-origin aliases are not supported by this profile. An explicit localhost
  exception exists only for the standalone development probe.
- Strict DER signature parsing with positive, minimally encoded, in-range
  scalars. P-256 coordinates must be in range and on the curve.
- Bounded CBOR and client JSON parsing, including duplicate-key rejection,
  definite CBOR lengths, bounded nesting/items and exact consumption. Unknown
  client-data members are tolerated within those limits; unsupported CBOR types
  fail closed. This is deliberately not a general-purpose CBOR implementation.

## Credential state

Registration returns backup eligibility, current backup state and signature
counter. With prior state supplied, assertions must preserve backup eligibility.
Both counters being zero is valid, including for synced passkeys. If either
counter is nonzero, this profile requires an increase. A counter rollback is
rejected; it is not described as proof of cloning. Backup state may change.

Production adapters must persist this state with the credential metadata and
commit updated state only after successful verification. Public binding encoding v2 now carries this state. Enrollment
chains it through both assertions; the unlock callback receives an updated
binding for the consumer to persist atomically. Legacy v1 SDK bindings fail
structural validation; there is no silent state reset.

The original standalone probe saved SPKI metadata without these state fields.
It remains usable for the real-provider restart test: the first verified
assertion establishes a baseline for this run, and the second must preserve
eligibility and satisfy counter policy. This does not establish counter
continuity across old probe runs. No replacement enrollment or silent public
binding migration occurs.

## Remaining trust boundary

WebAuthn signatures authenticate authenticator data and the client-data hash.
They do not independently authenticate the PRF client-extension bytes. The
browser/provider and deployed helper code remain trusted for PRF output and its
association with the ceremony. Encrypted pairing binds transport to the selected
session; it does not make malicious helper code safe or attest a signed CLI.

No hardware provenance is asserted by `none` attestation. A successful result
is not evidence that the passkey is device-bound, that syncing preserves PRF on
another device, or that the provider works offline.

## Validation

Node WebCrypto/OpenSSL generates signatures independently of the Dart verifier.
Tests cover valid registration/assertions, changed signatures/keys/IDs, signed
wrong contexts and flags, counter behavior, malformed encodings, every truncated
registration prefix, hostile nesting, duplicate keys and saved-binding reuse.
The HTTP tests also carry the evidence across the real encrypted loopback bridge,
then corrupt public evidence after browser verification to ensure Dart rejects it.
Synthetic PRF values are used for these automated tests, never provider secrets.

A real-provider saved-credential run passed both Dart assertion checks and
decrypted the earlier process's encrypted marker; see [validation receipts](validation.md).
It reused a legacy SPKI binding, so raw registration verification still needs a
real-provider run. Persisted state continuity is covered with independent signed fixtures.
Real native-provider continuity and independent security review remain pending.

References: [WebAuthn registration](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential),
[assertion verification](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion),
[PointyCastle](https://pub.dev/packages/pointycastle/versions/4.0.0).


## Direct hardware profile

`WebAuthnVerifier.hardware` is separate from the WebAuthn-origin profile. It
accepts a fresh local ceremony hash from the trusted hardware backend, not a
fabricated HTTPS origin. It reuses bounded COSE/CBOR parsing and ES256 assertion
verification with the saved credential, RP hash, user handle, UP/UV and counter
policy.

Registration is accepted only after native libfido2 verifies its attestation
signature against the requested challenge hash. Dart additionally requires
signed `hmac-secret=true` and `credProtect=3` enrollment extensions. There is no
manufacturer chain-validation or hardware-provenance claim. Hardware bindings
must not be backup-eligible.

Assertions require the signed hmac-secret encrypted-output extension (32 or 48
bytes for a single output, depending on the PIN/UV protocol). The decrypted
32-byte output comes from libfido2's matching CTAP session. The native library
and process remain trusted to associate decrypted output with this evidence.
The core then proves repeatability through two fresh verified assertions.

Independent Node/OpenSSL fixtures cover the direct local hash, WebAuthn PRF salt
normalization, altered signatures, signed wrong RP/challenge/flags/extensions,
credential protection, replay/counter rollback and v3 binding validation.
See the hardware section of [validation](validation.md) for build/device scope.
