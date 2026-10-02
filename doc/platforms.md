# Platform integration and consumer setup

The portable abstraction is credential creation plus verified PRF recovery.
The [consumer SDK guide](sdk.md) owns the Dart API contract.
The [implementation plan](implementation-plan.md#accepted-scope--2026-09-29)
owns accepted scope: native OS providers plus physical FIDO2 keys, with hardware
access for desktop CLIs. Browser/extension delivery is deferred.

Existing Apple/Android/Windows provider adapters remain experimental. The
tested macOS release host has verified normal-constructor enrollment, restart
decryption and cancellation/retry. A physical iPhone passed those core checks
with a diagnostic wrapper. Broader lifecycle/provider coverage remains open;
Android real-provider and Windows runtime checks remain outstanding. A libfido2 USB hardware adapter is implemented for macOS/Linux;
the iPhone NFC adapter recovered the Mac-created marker with the same physical
key. Broader NFC lifecycle/device qualification remains open. Android USB/NFC
implementation builds and passes native tests; a Pixel 6a / Android 16 debug
consumer decrypted the Mac-created marker over NFC with the same key. Android
USB, restart and broader lifecycle/packaging qualification remain pending.
Wired iPhone USB and Windows hardware remain pending. The shared [provider demo](../demo/provider_app/README.md)
uses Flutter solely as the native-app test embedder, with the standalone SDK
accessed through FFI. Exact executed proof lives in [validation](validation.md).

## Target matrix

Every row is a target, not a blanket support claim. PRF and user verification
must be supported by the selected provider or physical credential.

| Host | OS-provider route | Physical-key route and setup |
| --- | --- | --- |
| Signed macOS app | AuthenticationServices; signing, associated-domain entitlement and AASA | USB through direct adapter; an OS-mediated route follows Apple's API requirements |
| iOS/iPadOS app | AuthenticationServices; signing, AASA and active UIKit scene | Phone NFC and supported wired configurations; native SDK/entitlements and device qualification |
| Android app | Credential Manager; Digital Asset Links with app signing fingerprints and Activity bootstrap | Generic Android USB HID/NFC plus YubiKit CTAP; AAR, device permissions, foreground Activity and app PIN UI; no domain association |
| Windows app | Existing WebAuthn adapter; app-owned window and qualified provider/OS PRF | Qualify OS-mediated security-key access and normal-user deployment |
| Desktop CLI on macOS/Linux/Windows | Not a release requirement; no browser helper or extension required | Physical FIDO2 key, native library packaging, stable namespace and an interactive verification flow |
| Linux desktop app | No qualified OS-provider backend | Direct physical key, device permissions and native packaging |

USB is the desktop baseline. NFC on computers requires a separately supported
external reader; phone NFC support does not imply arbitrary reader compatibility.
A YubiKey Bio is a fingerprint-capable USB model, not an NFC model. Actual
hardware capability checks take precedence over a brand label.

The same hardware credential should work across supported hosts/transports when
its identity, PRF input normalization and verification policy remain consistent.
This is a qualification target. Creating another credential on another key or in
a provider produces a separate unlock method. Credential portability does not
establish Keybay vault portability.

## OS-provider setup

- [Apple package, signing, AASA and host setup](../native/apple/README.md)
- [Android AAR, Digital Asset Links and automatic bootstrap](../native/android/README.md)
- [Windows DLL and owner-window rules](../native/windows/README.md)

AASA's webcredentials association and Android's credential-sharing Digital Asset
Links are consumer-owned public metadata. Android URL App Links alone are not
the credential-sharing contract. There are no Keypass API keys or accounts; see
the [runtime independence constraint](implementation-plan.md#runtime-independence-constraint).

Construct `Keypass.system(rpId: 'vault.example.com', displayName: 'Example App')`
once and reuse it. The RP ID is explicit and stable; display name defaults to
that identifier. Keypass does not read runtime pubspec files, environment
variables or infer a domain from associated domains. Native libraries must
currently be linked by the app packager; `dart pub get` alone does not build
them. The same `check/create/unlock` contract applies to direct hardware through
`Keypass.hardware(rpId: 'vault.example.com')`. Results own temporary secrets and
must be disposed; clients need no disposal. The same RP ID can be used by both
routes; this does not make separately created credentials interchangeable.

Apple requires a presentation anchor, Android a foreground Activity and Windows
an owner window. Existing adapters resolve unambiguous hosts automatically.
Custom embedders may need one native registration callback; ordinary Dart calls
should not take per-operation host handles. Entitlements alone do not provide
the native library or UI lifecycle.

## Hardware setup

The macOS/Linux USB slice uses `Keypass.hardware(rpId:, requestPin:,
selectConnection:, onEvent:)`. See its [build and consumer instructions](../native/hardware/README.md).
The [iPhone NFC adapter](../native/hardware_apple/README.md) uses the same API,
standard FIDO CTAP and capability checks, without vendor-ID filters. It needs
NFC signing/entitlements and PIN UI, but no domain association. `check()`
identifies a ready reader; only a ceremony checks a key.
The [Android USB/NFC adapter](../native/hardware_android/README.md) uses platform
device APIs and the SDK's FIDO protocol layer. Its AAR starts automatically through
AndroidX Startup; USB access needs OS permission and NFC uses in-app reader mode.
It shares the hardware namespace and PIN/selection callbacks, without Digital
Asset Links or a website. Native packaging is currently manual.
The remaining adapters and acceptance gates live in
[the hardware milestone](implementation-plan.md#2-add-the-hardware-route).
Direct SDK/CTAP access does not require hosting an RP website. Its stable
namespace is not authentication of the local executable. OS-mediated device
access follows the OS API's separate identity/presentation requirements.

Package native dependencies, request necessary device/NFC permissions, and expose
safe PIN/touch/cancellation prompts. Capability detection must not weaken the
verification policy or silently replace the credential. NFC read loss and USB
removal should produce a bounded retry/error without changing enrollment.

Keypass owns the credential/PRF interaction and returns a temporary result plus
an opaque recovery record. The consumer owns key derivation context, encrypted
envelopes, record integrity, transactional updates and recovery policy.
Do not add a general-purpose YubiKey management surface to the public API.

## Historical browser proof

The [standalone browser probe](browser-probe.md) remains available for research.
It proved Google Password Manager PRF equality across separate JIT/AOT processes
on macOS localhost. It is not wired into the public API and is no longer the
selected CLI delivery route. The [CLI investigation](research/2026-09-29-cli-passkey-access.md)
records the earlier alternatives, not current implementation commitments.

## Provider behavior

OS dialogs select the provider and verification method. Do not promise
fingerprint-only access or portable provider-name selectors. A passkey may be
synced or device-bound. Sync alone is not proof of PRF equality, cross-provider
interchange or offline access. Losing every enrolled credential requires a
separately configured recovery method in the consuming application.
