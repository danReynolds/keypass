# FIDO2 security-key vault unlock investigation

> Research snapshot copied from Keybay. See the [implementation plan](../implementation-plan.md)
> for current Keypass implementation status.

Investigated 2026-09-28 against Keybay
`d71eb38b9a78e78a03e9ba4aaf035d48f4a5729a`.
This is source/API research and a proposed implementation direction. No physical
security key was enrolled, no hardware round trip was tested, and no dependency
or production code was changed.

## Recommendation

Build a small Flutter-free Dart package that exposes credential enrollment and
credential-bound secret derivation, backed by existing native implementations.
Use Keybay as the first consumer. Prefer libfido2 for Linux/macOS, Windows
WebAuthn for Windows, YubiKit Android for an initial Android implementation, and
evaluate Apple AuthenticationServices alongside YubiKit Swift for iOS.

There is no inspected package that supplies the complete combination of:

- no Flutter runtime dependency;
- external FIDO2 security keys, with hmac-secret/PRF output;
- desktop CLI and mobile host integration;
- consistent derivation, cancellation, user-verification and failure behavior;
- the packaging and hardware evidence needed for a Keybay release.

This does not require implementing the FIDO protocol or its cryptography from
scratch. The work is primarily adapters, packaging, interaction/lifecycle
handling, policy, and device qualification. A uniform Dart API is reasonable;
uniform installation and transport support across every OS/device is not.

## What operation Keybay actually needs

A successful signature or a boolean authentication result is insufficient.
Enrollment must create a credential with hmac-secret/PRF support and prove it
can return a reproducible secret. Unlock evaluates that credential's PRF using
stored method metadata, then derives a purpose-bound wrapping key with HKDF.
The result cryptographically opens a store-key envelope inside Keybay's
existing platform-protected package.

Store the credential ID, relying-party identity, PRF input, derivation version,
verification policy and authenticated envelope metadata. Do not persist the
derived secret in the ordinary platform keystore: doing so would remove the
independent hardware requirement.

Normalize adapters to WebAuthn PRF semantics. Direct CTAP hmac-secret takes a
32-byte salt; WebAuthn PRF first applies
`SHA-256("WebAuthn PRF\0" || input)`. Apply that transformation exactly once.
Also require consistent user verification: CTAP distinguishes secrets derived
with and without user verification. A touch is user presence, not necessarily
PIN/biometric verification. These choices need cross-backend test vectors.
[WebAuthn PRF specification][prf-spec]

The package should have explicit enrollment/evaluation/cancellation operations,
capability results and typed failures. It should not be a generic
`authenticate(): bool` library or a vault-storage library. Keybay owns its
envelopes, policy, sessions and rotations. Existing record operations remain
prompt-free after explicit opening.

## Dart and Flutter candidates inspected

Versions below were fetched from pub.dev's package API, and their published
archives were inspected without installing or executing them. Search results
were sometimes stale; the package API and archive supplied the versions here.

| Candidate | Evidence | Decision |
| --- | --- | --- |
| `fido2` 2.0.1 | Flutter-free Dart API, Rust native/WASM crypto backend, CTAP models, PIN protocols and WebAuthn verification. Caller supplies `CtapDevice.transceive`; no hmac-secret/PRF implementation was found in published `lib/`. Requests accept generic extension maps. | Relevant protocol reference or a contribution target, but it leaves the native transports and secret-extension handling to us. Prefer established native implementations for this narrow feature. |
| Corbado `passkeys` 2.23.1 | Flutter plugin with PRF request/response APIs, Android/iOS/macOS/web/Windows adapters, no Linux adapter. | Best broad Flutter integration reference inspected; cannot be a direct dependency of the standalone Dart package. |
| `passkeys_darwin` 0.4.5 | PRF is set on the **platform** request and extracted from the platform response. The separate physical-security-key request/response branches do not wire PRF. | Its iOS 18+/macOS 15+ PRF support does not establish physical-key secret derivation. Need our own physical-key path or an upstream contribution. |
| `passkeys_windows` 0.1.5 | Uses native WebAuthn hmac-secret/PRF fields and returns derived output; useful cancellation and threading reference. | Useful native reference, still Flutter-owned host plumbing. |
| `yubikey_flutter` 0.1.0 | Android/NFC bridge to YubiKit. FIDO registration/assertion pass null extension inputs. Its secret-producing challenge-response method uses the separate OTP application's HMAC-SHA1 feature. | Useful lifecycle reference, not the FIDO2 hmac-secret implementation we need. |
| `webauthn_secure_storage` 0.2.3, Linux adapter 0.2.0 | Linux uses libfido2 for credential creation/assertion; inspected Linux source does not implement hmac-secret/PRF. | Linux WebAuthn support is not evidence of Linux vault-key derivation. Broad storage scope also overlaps Keybay. |
| `maktub_passkey` 0.1.0-dev.4 | Flutter PRF API for platform/synced credentials on iOS and Android; no desktop implementation. | Narrow PRF API inspiration, not a cross-platform external-key backend. |

The `fido2` 1.x README described exclusively Dart source; 2.0.1 uses Rust.
Native source is acceptable for this project, but adopting that package would
still require reviewing and distributing its native build.

Sources: [fido2][dart-fido2], [passkeys][passkeys],
[Darwin implementation][passkeys-darwin], [Windows implementation][passkeys-windows],
[yubikey_flutter][yubikey-flutter], [Linux storage adapter][storage-linux],
[maktub_passkey][maktub]. This was a fit assessment, not a complete security audit.

## Native foundation and platform work

### Linux

libfido2 is an established C implementation supporting CTAP and hmac-secret.
It is suitable for a small Dart FFI boundary. Its upstream dependency set
includes libcbor, OpenSSL and zlib, plus libudev on Linux. It uses a BSD-2-Clause
license. [libfido2 documentation][libfido2]

Our work: credential operations and buffers, asynchronous calls, PIN/UV and
touch interactions, cancellation/unplug behavior, and library distribution.
Consumers need device access, commonly supplied by distro udev rules. Sandbox
packaging such as Flatpak/Snap needs separate device-access qualification;
ordinary desktop support does not automatically prove sandbox support. No
authentication server or API key is required for direct token access.

### macOS

Use the same libfido2 boundary for a CLI-friendly USB path. Package the native
library and dependencies for supported architectures, and qualify signing,
notarization and any sandbox USB entitlement requirements for the actual host.
This direct route does not require Apple's passkey associated-domain setup.
An AuthenticationServices path is possible for app consumers but brings its
presentation and domain requirements.

### Windows

Prefer a narrow binding to the OS WebAuthn API. It exposes PRF/hmac-secret input
and output, cancellation and authenticator attachment selection. Require an
external authenticator and appropriate UV policy rather than silently accepting
Windows Hello or another credential type. Check WebAuthn API version and
extension output at runtime. [Microsoft assertion options][windows-options]

libfido2 also supports Windows and has a WebAuthn-backed path, but adopting that
path requires confirming it exposes the exact authenticator policy we need.
Do not make administrative USB access a normal consumer requirement. Windows
host/UI ownership and cancellation still require a device-tested integration.
Keybay's Windows platform protector remains a separate unfinished commitment
in the current RFC; a Windows FIDO package does not complete that provider.

### Android

YubiKit Android implements hmac-secret/PRF and USB/NFC device access. The current
release notes list 3.2.1. Its core/native implementation is usable without
Flutter. [SDK overview][android-sdk], [extension API][android-hmac],
[release notes][android-releases]

Our package needs a Kotlin/Java bridge, Gradle artifact and activity/context
integration. USB permission, NFC discovery, PIN entry, cancellation and activity
lifecycle must work through a host callback or native UI. This is more than a
Dart pub dependency: Keybay's existing boot-class JNI access does not itself
install a third-party Java SDK or supply these lifecycle callbacks.

The SDK's optional FIDO UI module is marked experimental; avoid treating its
API as a stable foundation without a version-pinning decision. YubiKit is
primarily qualified for YubiKeys. Supporting other vendors is a separate
transport/device qualification task, even when the protocol is standard.
Credential Manager offers another route but provider support for PRF on
external keys needs direct evidence, not an inference from platform-passkey
support. [Android host setup][android-host], [FIDO UI module][android-ui]

### iOS / iPadOS

There are two real routes, with different consumer tradeoffs:

1. **Apple AuthenticationServices on iOS/iPadOS 26.4+.** Apple's current symbol
   metadata marks the physical-security-key registration and assertion `prf`
   properties as introduced in 26.4 (also macOS/Mac Catalyst 26.4). This is
   distinct from platform-passkey PRF on iOS 18/macOS 15. Use a Swift/Objective-C
   bridge and system presentation. Consumers need an associated domain with
   `webcredentials`, the entitlement and a hosted AASA file. A local vault does
   not inherently need an authentication backend; domain verification is still
   a deployment requirement, and cold/warm offline behavior must be tested.
   [Assertion PRF][apple-prf], [registration PRF][apple-prf-register],
   [Apple physical-key integration][apple-security-keys]
2. **YubiKit Swift for direct token communication.** The tagged **v1.4.0** source
   includes `CTAP2.Extension.HmacSecret` and `WebAuthn.Extension.PRF`; this is not
   merely development-branch code. The SDK declares iOS 16+/macOS 13+ and Swift
   6.1. This makes a direct NFC path a serious prototype candidate for older
   iPhones. Its docs also describe SmartCard/Lightning transports, but USB HID
   is macOS-only. The existence of USB SmartCard APIs does not prove FIDO works
   over USB for every key/device. Qualify iPhone/iPad and each transport
   separately. NFC requires entitlement, permitted application identifiers and
   usage text. [Tagged PRF code][swift-prf], [tagged HMAC code][swift-hmac],
   [SDK configuration][swift-setup]

An older Yubico PRF guide says Swift lacks this capability; current tagged code
supersedes that statement. The Swift SDK also explicitly documents that it does
not zeroize sensitive data. Review that limitation before claiming compatibility
with Keybay's secret-lifetime expectations. [Tagged README][swift-readme]

**Do not promise that one YubiKey model, one connector, or one minimum iOS version
covers every Apple device.** The first mobile spike must enroll and derive a
secret with real hardware, including an iPad if iPad support is claimed.

## Consumer-facing configuration

No vendor API key, paid service or account is intrinsic to local FIDO vault
unlock. Consumers may need a stable relying-party ID/name, display/presentation
context, and host-level native initialization. Keybay should own vault salts,
credential metadata and wrapping details.

Direct SDK paths can perform operations locally. The Apple OS path additionally
requires a domain association; Android Credential Manager would introduce its
own association/provider requirements. That difference should be an explicit
backend/setup choice, not hidden behind a promise of universal zero setup.

Support should be reported for the operation and device: external credential
creation, secret derivation, PIN/UV, available transport and cancellation.
An unsupported key or missing PRF output must fail closed. No downgrade to a
signature-only UI gate, platform passkey or platform-only Keybay unlock.

Cross-platform support means a consistent security contract on each platform.
It does not add portable/synchronized vault files: Keybay retains its independent
platform binding.

## Keybay work beyond native adapters

The [current RFC](https://github.com/danReynolds/keybay/blob/d71eb38b9a78e78a03e9ba4aaf035d48f4a5729a/doc/rfcs/0001-per-application-stores.md#managing-unlock-methods)
supports only a singleton passphrase method in the shipped format. It explicitly
requires a reviewed follow-up design for retaining alternative unlock routes
during store-key rotation and revoking methods without possessing every token.
Adding a few FFI calls does not solve that problem.

Required work includes a versioned key-package format; authenticated method
metadata; enrollment and round-trip confirmation; passphrase/token alternatives;
backup-token enrollment; removal/rekey/revocation; migration and interrupted
mutation behavior; clear lost/reset-token failures; and CLI/consumer interaction.
Adding an alternative remains OR policy. Requiring passphrase AND token is a
separate feature and excluded from the estimate below.

## Effort estimate and first proof

Planning estimate for one experienced Dart/native engineer, with the needed
hosts and keys available. These are effort ranges, not measurements or delivery
dates. Independent security-review scheduling is additional.

| Workstream | Estimated effort |
| --- | --- |
| Feasibility spike: macOS, Android, and chosen iOS route; compare derived output; validate PIN/UV and cancellation | 3–5 engineer-days |
| Dart contract, macOS/Linux bindings, Windows adapter and native packaging | 8–12 days |
| Android/iOS bridges, lifecycle, mobile packaging and transport handling | 8–12 days |
| Keybay envelope policy, format evolution, rotation/revocation and consumer flow | 5–10 days |
| Hardware regression matrix, distribution checks, examples and documentation | 5–10 days |

That is approximately **6–10 engineer-weeks** for the supported-platform feature,
excluding completion of Keybay's Windows storage provider, web vault support,
AND/MFA policy, and an exhaustive vendor/transport matrix. A focused macOS/Linux
release is roughly **4–6 weeks**, depending on the multi-method design. Older-iOS
transport gaps or stronger memory-erasure requirements could increase this.

First prove the difficult boundaries before freezing the public API:

- enroll a disposable credential and recover the same 32-byte result across
  restarts and relevant backends, without logging secret output;
- show wrong key, missing key, missing PRF, cancellation, unplug and blocked PIN
  leave the vault locked and do not mutate its policy;
- test actual mobile transport/device combinations and the claimed offline path;
- exercise passphrase recovery and a second enrolled token through rotation and
  removal, including interrupted writes and obsolete file snapshots;
- qualify a non-Yubico authenticator before advertising broad vendor support;
- verify packaged Dart AOT/CLI and native mobile hosts, not only Flutter samples.

Sources and downloaded archives were inspected in
`/private/tmp/keybay-fido2-research-20260928`. Public Swift v1.4.0 source files
were checked at tag commit `e19212f2efbca9af280e57542e669885de5acdc1`.
Some rendered web search results lagged current package/API data. No hardware
test, package installation, or production readiness claim is implied.

[prf-spec]: https://www.w3.org/TR/webauthn-3/#prf-extension
[dart-fido2]: https://pub.dev/packages/fido2/versions/2.0.1
[passkeys]: https://pub.dev/packages/passkeys/versions/2.23.1
[passkeys-darwin]: https://pub.dev/packages/passkeys_darwin/versions/0.4.5
[passkeys-windows]: https://pub.dev/packages/passkeys_windows/versions/0.1.5
[yubikey-flutter]: https://pub.dev/packages/yubikey_flutter/versions/0.1.0
[storage-linux]: https://pub.dev/packages/webauthn_secure_storage_linux/versions/0.2.0
[maktub]: https://pub.dev/packages/maktub_passkey/versions/0.1.0-dev.4
[libfido2]: https://developers.yubico.com/libfido2/
[windows-options]: https://learn.microsoft.com/en-us/windows/win32/api/webauthn/ns-webauthn-webauthn_authenticator_get_assertion_options
[android-sdk]: https://developers.yubico.com/yubikit-android/
[android-hmac]: https://developers.yubico.com/yubikit-android/JavaDoc/fido/2.8.2/com/yubico/yubikit/fido/client/extensions/HmacSecretExtension.html
[android-releases]: https://developers.yubico.com/yubikit-android/Release_Notes.html
[android-host]: https://developers.yubico.com/yubikit-android/android/index.html
[android-ui]: https://developers.yubico.com/yubikit-android/fido-android-ui/index.html
[apple-prf]: https://developer.apple.com/documentation/authenticationservices/asauthorizationsecuritykeypublickeycredentialassertionrequest/prf-99zke
[apple-prf-register]: https://developer.apple.com/documentation/authenticationservices/asauthorizationsecuritykeypublickeycredentialregistrationrequest/prf-2ys9l
[apple-security-keys]: https://developer.apple.com/documentation/authenticationservices/supporting-security-key-authentication-using-physical-keys
[swift-prf]: https://github.com/Yubico/yubikit-swift/blob/v1.4.0/YubiKit/YubiKit/FIDO/WebAuthn/Extensions/WebAuthnPRF.swift
[swift-hmac]: https://github.com/Yubico/yubikit-swift/blob/v1.4.0/YubiKit/YubiKit/FIDO/CTAP/Extensions/HmacSecret.swift
[swift-readme]: https://github.com/Yubico/yubikit-swift/blob/v1.4.0/README.md
[swift-setup]: https://yubico.github.io/yubikit-swift/documentation/yubikit/gettingstarted
