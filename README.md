# Keypass

Passkey-derived encryption secrets for Dart applications, without Flutter.

Keypass is being built to enroll passkeys through OS credential providers or
physical FIDO2 security keys and obtain repeatable [WebAuthn PRF](https://www.w3.org/TR/webauthn-3/#prf-extension)
output. Applications such as Keybay can use that output to protect encryption keys.
The provider handles the passkey and verification UI; Keypass does not read
fingerprints, face data, or a passkey's private signing key.

**Status: experimental OS-provider, desktop USB and phone hardware adapters.** Swift
macOS/iOS, Kotlin/JNI Android and Windows WebAuthn adapters feed the same Dart
verifier and binary-secret transport. The signed macOS FFI demo passed enrollment,
fresh-process decryption and cancellation/retry through the normal public client.
A physical iPhone passed those core checks with a diagnostic backend wrapper;
the undecorated iOS path and broader lifecycle coverage remain to be verified.
Android has emulator host smoke evidence; real-provider verification is deferred.
A shared Flutter test app exercises packaged native FFI consumers without adding
Flutter to the SDK. Windows has cross-compiled. See [consumer setup](doc/platforms.md)
and the scoped [validation receipts](doc/validation.md).

The new direct USB adapter uses libfido2 and the public
[Keypass.hardware API](native/hardware/README.md). It requires verified
`hmac-secret` output, a PIN or configured on-key verification, and touch. Provider
bindings keep their existing encoding; hardware bindings explicitly carry their
route. The [iPhone NFC adapter](native/hardware_apple/README.md) now implements
the same contract with standard FIDO CTAP through pinned YubiKit Swift. Physical
hardware support is capability-based, without vendor allowlists. Native packaging
is still manual. The [Android USB/NFC adapter](native/hardware_android/README.md)
is implemented with generic Android connections and the YubiKit FIDO protocol
library. A physical Pixel 6a recovered the Mac-created marker over NFC with the
same key; Android USB and broader qualification remain pending. Wired iPhone USB and Windows hardware
remain unfinished. A physical YubiKey passed macOS USB
enrollment, matching secret evaluations and fresh-process authenticated
decryption through the standalone Dart CLI. The same key then decrypted that
Mac-created marker on the iPhone and Android over NFC. Other hardware paths and broader
failure/lifecycle checks remain unqualified; exact proof is recorded separately.

The separate browser probe recovered Google Password Manager's PRF output in a
fresh AOT CLI process and decrypted its earlier saved test marker. Browser-assisted
CLI access is now deferred. Configuration is explicit in the Dart constructors.
Native clients require the corresponding host library to be packaged; absent libraries
return `backendUnavailable`, and missing windows return `hostUnavailable`.
The package is unpublished; its API and binding encoding are not frozen.

## Consumer API

Configure a client once and reuse it. Each operation owns its native resources;
the client itself needs no disposal.

```dart
import 'package:keypass/keypass.dart';

final passkeys = Keypass.system(rpId: 'vault.example.com');
final readiness = await passkeys.check(); // Optional, no prompt.
if (!readiness.canAttempt) {
  // Present readiness.reason or an independently configured access method.
  return;
}

final result = await passkeys.create(label: 'Personal vault');
try {
  // Use result.secret with your purpose-bound KDF and key-wrapping scheme.
  // Atomically save result.record.toJson() with the authenticated envelope.
} finally {
  result.dispose();
}
```

For direct physical keys, construct the same interface with
`Keypass.hardware(rpId: 'vault.example.com', requestPin:, selectConnection:, onEvent:)`.
Supply your application's PIN/connection UI where required. The stable RP ID
scopes credentials; direct hardware access needs no hosted website.

| Operation | Result |
| --- | --- |
| `check()` | Prompt-free readiness to attempt an operation; not proof of PRF support |
| `create(label:, cancellation:)` | A new credential, two verified matching PRFs, and an owned `PasskeyResult` |
| `unlock(record, cancellation:)` | The existing credential's verified secret and updated record; no enrollment or fallback |

Both secret operations return the same `PasskeyResult`. Its `secret` is a
read-only byte view; `record` is opaque, nonsecret metadata with `toJson()` and
`PasskeyRecord.fromJson()`. Dispose the result in `finally`, even if wrapping or
persistence fails. Keypass clears its owned buffer; caller copies and derived
keys remain the caller's responsibility. Integrity-protect records and persist
advanced verification state transactionally.

**Always await secret-bearing operations.** Abandoning their Future or using
`Future.timeout` alone does not cancel native work or dispose a late result.
Cancel through `PasskeyCancellation`, await settlement, and dispose any result
that succeeded. `check()` is optional: it reserves nothing, may throw `busy`,
and cannot guarantee a credential's PRF support.

See the **[consumer SDK guide](doc/sdk.md)** for both routes, hardware callbacks,
cancellation, ownership and complete persistence responsibilities. Applications
own encryption, storage, synchronization and recovery policy.

System-provider RP IDs are app-associated domains, not API endpoints. Apple and
Android still require domain association, signing and native host integration.
Native packaging is currently manual; adding the Dart dependency does not
configure an app host. Keypass requires no Keypass-operated runtime website,
API, relay or account service; see the
[runtime independence constraint](doc/implementation-plan.md#runtime-independence-constraint).

Desktop CLIs target direct physical-key access. USB and phone NFC are in scope;
no browser helper or extension is required by the accepted product plan.
The [standalone browser probe](doc/browser-probe.md) remains separate research
and is not wired into the public API.

| Target | Planned integration | Current implementation |
| --- | --- | --- |
| Signed macOS apps / iOS | OS providers plus physical keys | Apple provider adapter; macOS normal-client and iPhone diagnostic-host enrollment/restart/cancel-retry verified; macOS USB enrollment/restart also verified with a physical YubiKey; iPhone NFC recovered the Mac-created marker with the same key |
| Android | OS providers plus USB/NFC physical keys | Credential Manager AAR/JNI and emulator smoke; generic USB/NFC hardware module; Pixel 6a NFC decrypted the Mac-created marker with the same key in the debug demo; real provider, USB and broader qualification pending |
| Windows | Native providers and physical keys | WebAuthn adapter cross-compiled; runtime and physical-key access unqualified |
| Linux / desktop CLIs | Direct physical FIDO2 keys | libfido2 USB adapter and standalone Dart CLI implemented on macOS/Linux; other hardware adapters pending |

These are targets, not supported-platform claims. Provider PRF support and
cross-device behavior must be tested for each supported path.

Try the [interactive platform demos](doc/demo.md), or see the [implementation plan](doc/implementation-plan.md),
[native backend contract](doc/backend-contract.md),
[consumer SDK](doc/sdk.md), [platform setup](doc/platforms.md), and
[Keybay integration](doc/keybay-integration.md).

## Development

```sh
dart pub get
dart format --output=none --set-exit-if-changed lib test example tool demo/provider_app/lib/store.dart
dart analyze --fatal-infos
dart test
node --test test/browser/ceremony.test.mjs test/browser/failure.test.mjs test/browser/gesture.test.mjs test/browser/deadline.test.mjs
dart run example/keypass_example.dart
```

Development tests require Node 22+ for WebCrypto interoperability. The SDK has
no Node or Flutter runtime dependency. Tests cover synthetic core lifecycle,
signed synthetic browser assertions and encrypted bridge failures. They do not
establish real provider, native UI, device, sync, offline or vault qualification.

Linux validation can also run in an isolated container:

```sh
docker build -f tool/validation/Dockerfile -t keypass-validation .
docker run --rm --network none keypass-validation
```

The build runs analysis, tests and AOT compilation. The final command only checks
CLI startup/help; it does not exercise a Linux desktop passkey provider. Docker
context exclusions keep local bindings and build/cache directories out of the image.
