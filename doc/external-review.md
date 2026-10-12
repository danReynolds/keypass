# External review guide

Prepared October 11, 2026. This is a review handoff, not a completed security
audit or an expanded platform-support claim. Pin an exact commit and retain the
resolved dependency manifests with the report.

## Source and published baseline

| Review target | Identity |
| --- | --- |
| Implementation baseline before this documentation update | [`d7d5316e66b0e6deebda74be1d62070a230af6c8`](https://github.com/danReynolds/keypass/tree/d7d5316e66b0e6deebda74be1d62070a230af6c8) |
| Latest published prerelease checked October 11 | [0.1.0-dev.2](https://pub.dev/packages/keypass/versions/0.1.0-dev.2), published October 6 |
| Pub archive SHA-256 | `9c46f2bb0413b4f891d5e7eddce46830d2fa4c5c83ebad08b14333efe051c1ec` |
| Consuming Keybay source baseline | [`162b4778075a4f303524d508015a019864634aa5`](https://github.com/danReynolds/keybay/tree/162b4778075a4f303524d508015a019864634aa5) |

The source includes [unreleased cleanup](../CHANGELOG.md#unreleased), including
mandatory saved verifier state and removal of prototype/native-path exceptions.
The published archive predates that cleanup. Its unchanged pubspec version is
not proof of byte-identical contents. Keybay currently pins the published
0.1.0-dev.2 package; it does not automatically consume this repository's main.
A joint test using a local override must record that as a separate configuration.

Capture `git rev-parse HEAD`, `git status --short`, Dart/native toolchain versions,
`pubspec.yaml`, `pubspec.lock`, native Gradle/Swift manifests and resolved library
versions. Desktop libfido2/OpenSSL/libcbor come from the build host within the
constraints in [build hooks](build-hooks.md); there is no single native dependency
version implied by the Dart package version. Record actual shipped libraries,
architectures, hashes and notices when reviewing an application artifact.

## Reading order and scope

1. [Security policy](../SECURITY.md): guarantees, trust boundaries and reporting.
2. [Consumer SDK](sdk.md): configuration, records, ownership, cancellation and
   the consumer's encryption/persistence obligations.
3. [Verifier](webauthn-verifier.md), [backend contract](backend-contract.md) and
   [native ownership](../native/OWNERSHIP.md): accepted evidence and result handoff.
4. [Platform setup](platforms.md) and [build hooks](build-hooks.md): app identity,
   dependencies, loading, permissions and lifecycle.
5. [Keybay integration](keybay-integration.md): the consuming encryption scheme,
   with a separate [Keybay review guide](https://github.com/danReynolds/keybay/blob/main/doc/external-review.md).
6. [Implementation plan](implementation-plan.md), [dated receipts](validation.md)
   and [prior API review](reviews/sdk-consumer-api.md): evidence and unfinished work.

Current guides describe the contract. `doc/research/` contains superseded
proposals, and validation entries describe the source/configuration at that
point in time. Old success receipts cannot qualify the current source wholesale.
The standalone browser probe is retained research; include it as a separate
scope if assessing its helper/loopback transport. It is not a public SDK route.

## Code and test map

| Boundary | Implementation | Evidence to inspect |
| --- | --- | --- |
| Public operations, route binding, ownership and cancellation | [client](../lib/src/client.dart), [record](../lib/src/record.dart), [result](../lib/src/result.dart), [cancellation](../lib/src/cancellation.dart) | `test/client_test.dart`, `test/binding_test.dart`, `test/readiness_cancellation_test.dart` |
| Parsing and cryptographic evidence | [verifier](../lib/src/webauthn/verifier.dart), [bounded CBOR](../lib/src/webauthn/bounded_cbor.dart), [client data](../lib/src/webauthn/client_data.dart) | `test/webauthn/`, `test/hardware/verifier_test.dart`; independently signed Node/OpenSSL fixtures |
| FFI transport and trusted backend glue | [system backend](../lib/src/native/backend.dart), [hardware backend](../lib/src/hardware/backend.dart), [C ABI](../native/include/keypass.h) | `test/native/`, `test/hardware/ffi_transport_test.dart`, cancellation and late-result fixtures |
| OS-provider adapters | [Apple](../native/apple/), [Android](../native/android/), [Windows](../native/windows/) | Native tests and CI compilation; physical receipts below have narrower scope |
| Physical-key adapters and PIN lifetime | [desktop](../native/hardware/), [iPhone NFC](../native/hardware_apple/), [Android USB/NFC](../native/hardware_android/) | Protocol/native ownership tests, terminal PIN tests, attended device receipts |
| Build/download/loading boundary | [hook](../hook/build.dart), [bundler](../hook/bundle.py) | `test/hooks/`, `tool/test_build_hooks.py`, package manifests and native notices |
| Example consumer persistence | [encrypted marker](../demo/provider_app/lib/store.dart) | `test/demo/store_test.dart`; a qualification example, not a production vault SDK |

Prioritize malicious/truncated evidence, RP/route/credential confusion, state
rollback and concurrent persistence, exact PRF/session binding, cancellation
before/after secret transfer, PIN cleanup, UI host loss and native-library loading.
Assess the trusted provider/backend boundary explicitly: validating WebAuthn
signatures does not independently validate system-provider PRF extension bytes.
Direct hardware RP namespaces do not identify the requesting executable. The
experimental Windows system route also lacks Apple/Android-style app/domain
association; a caller-configured origin is not proof of website control.

## Evidence and open work

| Evidence retained | What it establishes | Still open |
| --- | --- | --- |
| [macOS normal FFI flow](validation.md#macos-core-normal-ffi-flow-verified--2026-09-30) | Enrollment, fresh-process marker decryption, cancel/retry on the recorded host | Other providers/OS builds and wider lifecycle coverage |
| [iPhone recovery](validation.md#iphone-fresh-process-decryption-succeeds--2026-09-29-local-time) and subsequent cancel/retry entries | Diagnostic-host provider flow on the recorded phone | Undecorated iOS path and broader lifecycle/provider qualification |
| [macOS hardware](validation.md#macos-hardware-enrollment-and-fresh-process-decryption-verified--2026-09-30) | One physical YubiKey's enrollment and fresh-process decryption | Physical Linux sessions, additional keys/vendors/firmware, unplug/multiple-key failure matrix |
| [iPhone NFC](validation.md#physical-mac-usb-to-iphone-nfc-recovery--2026-10-01) and [Android NFC](validation.md#physical-mac-usb-to-android-nfc-recovery--2026-10-01) | Same Mac-created credential recovered the marker on both recorded phones | NFC enrollment, fresh-process repeats, connection-loss/cancel paths; Android USB and production packaging |
| Android provider host smoke; Windows builds | Host/ABI integration or compilation | Real Android OS-provider PRF, Windows runtime and direct hardware implementation/qualification |
| Dart/native synthetic tests and CI | Deterministic rejection, ownership, vectors and packaging paths | Human security audit, real-device sync/offline claims and full recovery matrix |

No completed independent human security audit is claimed. An available device,
a green build, a readiness probe or a login prompt is not proof of encrypted
recovery. One key's USB-to-NFC success does not qualify all FIDO2 hardware.
An old browser proof using a retired record does not qualify the cleaned-up probe.

## Reproduce and report

Install the [build prerequisites](build-hooks.md) deliberately, then run the
[README development checks](../README.md#review-and-development).
[CI](../.github/workflows/check.yml) defines the additional Swift, Android,
Windows and desktop native build/test lanes. `python3 tool/test_build_hooks.py`
checks relocated transitive CLI packaging without a credential ceremony.
For physical checks, use the [demo procedures](demo.md) with disposable data and
explicit user participation; do not reset a user's key or automate PIN retries.

A review report should name exact source/dependencies and artifacts, tested
platform/provider/firmware/transport, findings with reproducible impact and
severity, unreviewed areas, and residual assumptions. Keep secrets/PINs out of
logs and reports. Retain redacted receipts and hashes needed to reproduce
observations. Report undisclosed vulnerabilities privately using
[SECURITY.md](../SECURITY.md#reporting). Remediation and release qualification
are separate from completion of the review itself.
