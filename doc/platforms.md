# Platform integration

Native setup is required alongside the Dart dependency. The SDK has no Flutter
plugin or Keypass service. See [SDK usage](sdk.md) for the Dart API.

## Target matrix

| Host | System route | Direct hardware route |
| --- | --- | --- |
| macOS | Signed app, native library, AASA and active window | USB via Dart build hooks |
| iOS/iPadOS | Signed app, native library, AASA and active scene | iPhone NFC adapter; wired USB unimplemented |
| Android | Credential Manager AAR/JNI, Digital Asset Links and Activity | USB/NFC AAR, device permissions and Activity |
| Linux | No backend | USB via Dart build hooks and device permissions |
| Windows | Experimental WebAuthn DLL and owner window | Direct adapter unimplemented |

Physical evidence covers the recorded macOS provider flow, diagnostic iPhone
provider flow, one YubiKey over macOS USB, and recovery of that credential over
phone NFC. Android OS-provider and Windows runtime remain unqualified. See the
[review evidence matrix](external-review.md#evidence-and-open-work) for precise
coverage and gaps; the [receipt log](validation.md) retains device/build details.

## OS-provider setup

- [Apple](../native/apple/README.md): link the library, configure signing and
  `webcredentials`/AASA, and provide an active AppKit window or UIKit scene.
- [Android](../native/android/README.md): link the AAR/JNI bridge, configure
  credential-sharing Digital Asset Links with signing fingerprints, and provide
  a foreground Activity. URL App Links alone are insufficient.
- [Windows](../native/windows/README.md): package the DLL and provide an owner
  window. The configured RP/client origin does not prove website ownership or
  authenticate the executable; there is no Apple/Android-style association check.

Adapters discover unambiguous hosts automatically; custom embedders may need
native registration. Entitlements alone do not link libraries or provide UI
lifecycle handling. RP IDs remain explicit, stable client configuration.

## Hardware setup

- [Desktop USB](../native/hardware/README.md): [build hooks](build-hooks.md) prepare
  libraries during `dart run/test/build`, not `pub get`. Build hosts need native
  development dependencies; distribute the whole resulting bundle.
- [iPhone NFC](../native/hardware_apple/README.md): link the adapter and configure
  NFC signing, entitlements and usage description. No NFC simulator qualification.
- [Android USB/NFC](../native/hardware_android/README.md): link the AAR, obtain USB
  permission or use foreground NFC reader mode; Startup handles bootstrap.

Provide PIN/selection/cancellation UI where needed. Direct CTAP needs no website,
AASA or Digital Asset Links, but its RP namespace does not authenticate the caller.
Eligibility is capability-based, without vendor allowlists. Desktop NFC readers,
other key vendors/firmware and additional transports need separate qualification.
A phone NFC success does not establish desktop-reader or wired-phone support.

## Provider behavior

OS dialogs choose the provider and verification method; fingerprint-only access
is not promised. Sync does not guarantee PRF continuity, provider interchange or
offline access. A portable hardware credential does not make a Keybay vault
portable: its platform root remains required.

## Historical browser proof

The [browser probe](browser-probe.md) is separate research, not a public backend.
Browser/extension CLI delivery is deferred. Remaining work is in the
[roadmap](implementation-plan.md).
