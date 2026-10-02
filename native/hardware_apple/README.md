# iPhone NFC hardware adapter

Experimental implementation of the same `Keypass.hardware` contract as the
macOS/Linux USB adapter, using Core NFC and standard FIDO2 CTAP over ISO 7816
through [YubiKit Swift 1.4.0](https://github.com/Yubico/yubikit-swift/tree/v1.4.0).
The Dart SDK remains Flutter-free. The dependency is pinned; `Package.resolved`
records the tested transitive versions.

## Vendor-neutral scope

Physical FIDO2 authenticators are the target. The adapter selects the standard
FIDO application `A0000006472F0001`. It never selects a vendor management applet,
checks a vendor ID or AAGUID allowlist, reads serial numbers, or imposes
brand/firmware rules. PIN setup/reset, OTP, PIV and administration are outside scope.

Capabilities determine eligibility: `hmac-secret`, configured PIN or on-key
verification, and resident credentials with `credProtect=3` at enrollment.
Registration currently accepts packed ES256 certificate/self-attestation;
other formats fail closed. The signature check does not establish certificate
chain trust or manufacturer identity. Dart independently validates RP hash,
flags, credential binding, extensions, assertion signature and counter.

The SDK's low-level transport is generic, but its documentation is YubiKey-focused.
A synthetic arbitrary-AAGUID/APDU test does not qualify every vendor. Each
claimed key/firmware/transport combination still needs physical tests.

## Consumer setup

Initial target: an active iPhone app on iOS 18+, built with Swift 6.2+ for the checked-in dependency resolution.
NFC is unavailable in the simulator and on iPads without a reader. Wired iPhone
USB is not implemented by this package.

1. Link the `KeypassHardwareApple` Swift package product. Call
   `keypassHardwareVersion()` once to retain the object containing the C ABI,
   and export/retain `keypass_hardware_*` symbols for Dart FFI. The demo's
   `tool/configure_provider_demo.rb` shows its explicit packaging configuration.
2. Enable Near Field Communication Tag Reading for the app ID/profile. Add
   `com.apple.developer.nfc.readersession.formats = [TAG]` to signed entitlements.
3. Add `NFCReaderUsageDescription` and
   `com.apple.developer.nfc.readersession.iso7816.select-identifiers =
   [A0000006472F0001]` to Info.plist.
4. Use `Keypass.hardware(rpId:, requestPin:, selectConnection:, onEvent:)` with private PIN UI and
   cancellation handling. No Keypass service, website, API key, AASA or domain
   association is required for this direct hardware route.

The demo retains AASA solely for its separate OS-provider screen.

## Interaction and lifetime

`availability()` reports whether the host can attempt NFC. It never starts a
scan or proves that a key is present. Discovery returns one virtual NFC reader.
An explicit ceremony emits `HardwareEvent.presentKey` and opens the NFC sheet.

Configured on-key verification can finish in one scan. PIN-based verification
uses two: read capabilities/retry count, close NFC, ask the consumer for its PIN,
then scan the same key to authenticate and perform CTAP. Hold the key at the top
of the phone until each sheet closes. Enrollment registers then evaluates twice,
so it can need several scans/PIN prompts. There is no automatic PIN retry,
reset, credential replacement or route fallback.

PINs enter the ABI as writable bytes. PRF output uses a separate 32-byte binary
field, never JSON. Dart already normalized the WebAuthn salt: it is not hashed
again. USB/NFC preserve credential identity, input and verification policy.
A transport hint does not require re-enrollment.

Operations are serialized, cancelled on backgrounding and bounded by a
120-second deadline. The connection closes before reuse; late output is
discarded. YubiKit's global log level is set to critical to disable tracing.
Consumers must not enable transport tracing during secret-bearing operations.

Memory limitation: YubiKit accepts an immutable Swift PIN String and retains
immutable token/PRF copies internally. Keypass clears its mutable PIN/result
copies and native allocations, but cannot guarantee erasure of SDK, runtime,
Core NFC or UI copies. No raw secret is persisted. This remains a release
security-review item.

## Validation

From the repository root:

```sh
swift test --package-path native/hardware_apple
swift build --package-path native/hardware_apple \
  --triple arm64-apple-ios18.0-simulator \
  --sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)"
```

The signed [demo](../../demo/provider_app/README.md) has an isolated NFC screen
that imports the Mac ciphertext. Exact outcomes are in
[validation](../../doc/validation.md); compilation is not USB-to-NFC proof.
