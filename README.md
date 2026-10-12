# Keypass

Passkey-derived encryption secrets for Dart applications, without Flutter.

Keypass creates credentials through OS passkey providers or physical FIDO2 keys
and recovers repeatable 32-byte encryption material through WebAuthn PRF or
CTAP `hmac-secret`. A successful sign-in alone is insufficient. Keypass verifies
ceremony evidence and requires user verification; it does not read biometric
data or export a passkey's private signing key.

[Keypass 0.1.0-dev.2](https://pub.dev/packages/keypass/versions/0.1.0-dev.2)
is published as a prerelease. Current source also includes **unreleased**
cleanup listed in the [changelog](CHANGELOG.md). APIs and record encodings are
pre-1.0; publication does not establish support for every provider or device.
[Keybay 0.2.0](doc/keybay-integration.md) consumes the published package.

## Use the SDK

Configure a route once. Construction opens no device or dialog, and the client
needs no disposal. An RP ID scopes credentials; one RP ID can have many records.

```dart
import 'package:keypass/keypass.dart';

final passkeys = Keypass.system(rpId: 'vault.example.com');
final readiness = await passkeys.check(); // Optional; does not prompt.
if (!readiness.canAttempt) {
  // Explain readiness.reason through your application's UI.
  return;
}

final created = await passkeys.create(label: 'Personal vault');
try {
  // Derive a purpose-bound wrapping key from created.secret.
  // Atomically save created.record.toJson() with an authenticated envelope.
} finally {
  created.dispose();
}
```

On a later run, decode the saved nonsecret record and recover the same material:

```dart
final record = PasskeyRecord.fromJson(savedRecordJson);
final opened = await passkeys.unlock(record);
try {
  // Authenticate metadata and decrypt the original saved envelope.
  // Atomically persist opened.record.toJson() before publishing a session.
} finally {
  opened.dispose();
}
```

These sketches show the API boundary, not a complete encryption implementation.
The consumer owns encryption, integrity-protected metadata, atomic persistence,
concurrency and recovery. See the [SDK guide](doc/sdk.md) and
[executable encrypted-marker example](demo/provider_app/lib/store.dart).

For direct physical keys, configure `Keypass.hardware`:

```dart
final hardware = Keypass.hardware(
  rpId: 'dev.example.vault',
  requestPin: ui.requestPin,
  selectConnection: ui.selectConnection,
  onEvent: ui.onHardwareEvent,
);
```

`ui` represents application-owned handlers; their exact types and optional
behavior are in the [SDK guide](doc/sdk.md#configure-the-access-route-once).
Hardware access needs a stable RP namespace, native device access and a
compatible key; it needs no website or domain association. The namespace does
not authenticate the calling executable. Apple/Android system access uses the
app's associated domain and OS provider dialog. The experimental Windows adapter
uses a caller-configured RP ID without an app/domain association guarantee.
No Keypass account or API key
is required, and no Keypass-operated runtime service is involved.

| Operation | Contract |
| --- | --- |
| `check()` | Prompt-free readiness to attempt; no PRF or key-presence guarantee. |
| `create(label:, cancellation:)` | Register a new credential and verify two matching secret evaluations. |
| `unlock(record, cancellation:)` | Recover an existing credential's secret; never enroll or switch routes. |
| `PasskeyResult.dispose()` | Clear the owned secret buffer; neither delete the credential nor persist its record. |

Both secret operations return a `PasskeyResult` containing a borrowed read-only
`secret` and a new or updated `record`. Dispose it in `finally`. Caller copies,
derived keys and provider/runtime allocations are outside that wipe guarantee.
Records contain recovery and verification metadata, not the secret; keep them
integrity-protected and commit updated verification state after successful use.

Always await secret-bearing operations. `Future.timeout` alone does not cancel
native work or dispose a late result. Use `PasskeyCancellation`, await settlement,
and dispose any successful result. Readiness checks reserve nothing and may
report `busy`. See [ownership and cancellation](native/OWNERSHIP.md).

## Platform setup and evidence

| Route | Integration | Recorded evidence and remaining limits |
| --- | --- | --- |
| macOS / iOS system | Apple native library, signed app, associated domain/AASA, active window/scene | macOS ordinary-client enrollment, restart and cancel/retry; iPhone diagnostic-host equivalents. Broader provider/lifecycle and undecorated iOS-path qualification remain open. |
| Android system | Credential Manager AAR/JNI, signing/Digital Asset Links, foreground Activity | Emulator host smoke; physical OS-provider qualification deferred. |
| macOS / Linux hardware | USB adapter built by Dart hooks; OS device permissions | macOS YubiKey enrollment and fresh-process decryption. Linux builds/tests do not qualify a physical Linux key session. |
| iPhone hardware | Linked NFC adapter, NFC entitlement and foreground app | Mac-created credential decrypted over NFC; NFC enrollment and broader lifecycle checks remain open. Wired USB is unimplemented. |
| Android hardware | USB/NFC AAR, permissions and foreground Activity | Pixel 6a debug app decrypted the Mac-created marker over NFC. USB, restart and production packaging qualification remain open. |
| Windows | Native WebAuthn adapter | Build evidence only; runtime and direct hardware remain unqualified. |

See [platform setup](doc/platforms.md) for host requirements and
[validation receipts](doc/validation.md) for the exact devices, builds and
limitations. Hardware eligibility is capability-based, without vendor allowlists;
observations on one YubiKey do not qualify every FIDO2 key.

Desktop macOS/Linux USB libraries are built and bundled automatically through
[Dart build hooks](doc/build-hooks.md). Build hosts need the documented native
toolchain/development libraries; distributable CLIs must retain the whole native
bundle. OS-provider and mobile hosts still require explicit native linking,
signing, permissions and lifecycle setup. Adding a Pub dependency or entitlement
alone does not configure those hosts. Flutter is used only for test apps.

The [browser probe](doc/browser-probe.md) is retained research, outside the public
SDK. Browser-assisted CLI delivery is deferred. Keypass does not silently fall
back between system, hardware and browser routes.

## Review and development

Start an external review with the [review guide](doc/external-review.md) and
[security policy](SECURITY.md). They identify the source baseline, published
package, trust boundaries, code map, evidence and outstanding work. Historical
research and dated receipts are not current API specifications. The
[implementation plan](doc/implementation-plan.md) tracks remaining work.

With Dart 3.11+, Node 22+ and the [native build prerequisites](doc/build-hooks.md):

```sh
dart pub get --enforce-lockfile
dart format --output=none --set-exit-if-changed lib test example tool hook demo/provider_app/lib/store.dart
dart analyze --fatal-infos
dart test
node --test test/browser/ceremony.test.mjs test/browser/failure.test.mjs test/browser/gesture.test.mjs test/browser/deadline.test.mjs
dart run example/keypass_example.dart
```

These checks use synthetic fixtures and native packaging probes; they do not
perform an attended key ceremony. Native CI lanes are defined in
[check.yml](.github/workflows/check.yml). Use the [demo guide](doc/demo.md) for
explicit physical-provider tests with disposable data. MIT licensed.
