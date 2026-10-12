# Dart WebAuthn verifier

`lib/src/webauthn/verifier.dart` implements an internal, bounded verification
profile. The browser probe sends public ceremony evidence across its paired
channel and the CLI verifies it before processing or persisting the separate
PRF result. Native Apple/Android/Windows adapters now use the same verifier
before exposing their separate binary PRF output. There is no public browser
backend; the probe is separate research.

## Supported profile

- ES256 with a P-256 EC2 COSE key. PointyCastle 4.0.0 supplies SHA-256 and ECDSA
  verification in Dart; there is no Flutter or Node runtime dependency.
- Enrollment uses `attestation: none`. The verifier parses the original CBOR
  attestation object, requires an empty statement with format `none`, and obtains
  the credential ID and COSE key from its authenticator data. It does not trust
  separately supplied browser key material.
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
counter. Assertions must always preserve the saved backup eligibility.
Both counters being zero is valid, including for synced passkeys. If either
counter is nonzero, this profile requires an increase. A counter rollback is
rejected; it is not described as proof of cloning. Backup state may change.

Adapters persist this state with the credential metadata and commit updated
state only after successful verification. Both current system and hardware
records carry it. Enrollment chains it through both assertions; `unlock`
returns an updated record for the consumer to persist atomically.

The standalone browser probe now uses the same system records and verifier.
It retains backup/counter state across runs and atomically saves the updated
record with its encrypted marker. Old probe files are rejected; there is no
conversion or path that accepts missing verification state.

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
then corrupt collected public evidence before Dart verification to ensure rejection.
Synthetic PRF values are used for these automated tests, never provider secrets.

The early browser proof used a retired SPKI record. Current source rejects that
record and uses the common verifier with persisted state; the old browser receipt
does not qualify the cleaned-up probe. Later native macOS and diagnostic iPhone
receipts record enrollment and fresh-process decryption; see the
[current evidence index](external-review.md#evidence-and-open-work).
Independent signed fixtures cover persisted-state continuity. Broader native
provider/device qualification and an external human review remain open.

References: [WebAuthn registration](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential),
[assertion verification](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion),
[PointyCastle](https://pub.dev/packages/pointycastle/versions/4.0.0).


## Direct hardware profile

`WebAuthnVerifier.hardware` is separate from the WebAuthn-origin profile. It
accepts a fresh local ceremony hash from the trusted hardware backend, not a
fabricated HTTPS origin. It reuses bounded COSE/CBOR parsing and ES256 assertion
verification with the saved credential, RP hash, user handle, UP/UV and counter
policy.

Registration is accepted only after the native hardware adapter verifies its
attestation signature against the requested challenge hash (libfido2 on desktop;
the platform CTAP implementation on phones). Dart additionally requires
signed `hmac-secret=true` and `credProtect=3` enrollment extensions. There is no
manufacturer chain-validation or hardware-provenance claim. Hardware bindings
must not be backup-eligible.

Assertions require the signed hmac-secret encrypted-output extension (32 or 48
bytes for a single output, depending on the PIN/UV protocol). The decrypted
32-byte output comes from the native adapter's matching CTAP session. The native
library and process remain trusted to associate decrypted output with this evidence.
The core then proves repeatability through two fresh verified assertions.

Independent Node/OpenSSL fixtures cover the direct local hash, WebAuthn PRF salt
normalization, altered signatures, signed wrong RP/challenge/flags/extensions,
credential protection, replay/counter rollback and v3 binding validation.
See the hardware section of [validation](validation.md) for build/device scope.
