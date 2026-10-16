# Keypass

Passkey-derived encryption material for Dart, without Flutter.

Use an OS passkey provider or a physical FIDO2 key to create a credential and
recover the same 32-byte secret later. Keypass handles verification and native
interaction; your app owns encryption, storage and recovery. No Keypass service
or account is required.

**Prerelease:** [0.1.0-dev.3](https://pub.dev/packages/keypass/versions/0.1.0-dev.3).
Provider/device coverage is limited; see [platform setup](doc/platforms.md).
Source changes since publication are listed in the [changelog](CHANGELOG.md).

## Create and unlock

```dart
import 'package:keypass/keypass.dart';

final passkeys = Keypass.system(rpId: 'vault.example.com');
final created = await passkeys.create(label: 'Personal vault');
try {
  // Derive a wrapping key from created.secret.
  // Save created.record.toJson() with your authenticated encrypted envelope.
} finally {
  created.dispose();
}
```

Later, use the saved record to select the same credential:

```dart
final opened = await passkeys.unlock(PasskeyRecord.fromJson(savedRecordJson));
try {
  // Authenticate and decrypt the saved envelope using opened.secret.
  // Atomically save opened.record.toJson() before exposing the result.
} finally {
  opened.dispose();
}
```

The record is nonsecret recovery metadata; it needs integrity protection.
These sketches leave encryption and persistence to your app. See the
[SDK guide](doc/sdk.md) for the full contract and an executable example.
Always dispose results; clear your own derived keys and secret copies too.

## Choose a route

| Client | Setup |
| --- | --- |
| `Keypass.system(rpId:)` | Native app host and provider. Apple/Android require app/domain association. |
| `Keypass.hardware(rpId:, requestPin:, selectConnection:, onEvent:)` | Compatible FIDO2 key and native adapter. No website required; callbacks belong to your app. |

An RP ID scopes credentials; it can have many saved records. Direct hardware
namespaces do not authenticate the calling executable. Windows system support
is experimental and lacks Apple/Android-style domain association.

Desktop USB adapters use [Dart build hooks](doc/build-hooks.md); build hosts need
the listed native prerequisites. Mobile and OS-provider hosts need explicit
native setup. The browser probe is research, outside the public SDK.

`check()` optionally reports prompt-free readiness, not PRF support. To cancel,
use `PasskeyCancellation`, await settlement and dispose any successful result;
`Future.timeout` alone does not cancel native work.

## Documentation

- [SDK usage](doc/sdk.md) · [Platform setup](doc/platforms.md)
- [Security](SECURITY.md) · [External review](doc/external-review.md)
- [Keybay integration](doc/keybay-integration.md) · [Roadmap](doc/implementation-plan.md)

## Review and development

Requires Dart 3.11+, Node 22+ and the [native prerequisites](doc/build-hooks.md).

```sh
dart pub get --enforce-lockfile
dart analyze --fatal-infos
dart test
```

[CI](.github/workflows/check.yml) defines formatting, browser and native checks.
[Physical demos](doc/demo.md) use disposable data and attended credentials.
MIT licensed.
