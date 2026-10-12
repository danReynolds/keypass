# Keybay integration

Keybay SDK and CLI 0.2.0 are published with passkey protection through exact-pinned
Keypass 0.1.0-dev.2. Keypass has no dependency on Keybay. The
[Keybay SDK guide](https://github.com/danReynolds/keybay/blob/main/doc/sdk.md#add-passkey-protection)
owns the consumer API; [RFC 0003](https://github.com/danReynolds/keybay/blob/main/doc/rfcs/0003-passkey-methods.md)
owns the envelope construction and transaction rules.

## Consumer flow

Applications using Keybay do not construct a Keypass client or persist its records:

```dart
import 'package:keybay/keybay.dart';

const passkey = PasskeyCredential.system(rpId: 'vault.example.com');
final session = await Keybay.open();
try {
  await session.auth.add(passkey, label: 'Personal vault');
  await session.set('api-token', tokenFromOAuth);
} finally {
  await session.close();
}

// On a later run: authenticate an existing enrollment; do not create one.
final reopened = await Keybay.open(credential: passkey);
try {
  final methods = await reopened.auth.list();
  final selected = methods.whereType<PasskeyMethod>().single;
  await reopened.auth.remove(selected);
} finally {
  await reopened.close();
}
```

For an existing protected store, authenticate its current method before adding
another. Hardware uses `PasskeyCredential.hardware(rpId:, pin:)`, with optional
caller-owned UTF-8 PIN bytes. Keybay snapshots those bytes synchronously and
clears its copy; the caller must clear its own. Credentials have no UI callbacks.
System passkeys need a configured native app host and domain association;
standalone CLIs use hardware. Direct hardware needs no hosted RP website.

`open(credential:)` is authentication-only. A missing store fails with
`storeNotFound` before enrollment or platform-root creation. Credential-free
`open()` may initialize fully absent platform-only state. Enrollment is explicit
through `auth.add`, and must succeed before storing data that should require it.

Auth management is `add`, `list` and `remove(method)`, with no update or replace.
There may be zero or one passphrase and multiple passkeys, at most eight methods
in total. For passkeys, `open` may omit `methodId` only when exactly one enrollment
matches the RP ID and route. A method descriptor from `add`/`list` can be passed
to `remove`; it is checked against the vault and current enrollment.

Protection is `platform AND (passphrase OR passkey A OR passkey B ...)`.
Removing the last method explicitly returns to platform-only protection. Add and
remove are separate commits; prefer adding a replacement passkey first when
capacity permits. Removal neither deletes the provider credential nor revokes
previously copied complete snapshots.

## Ownership and cryptography

| Keypass owns | Keybay owns |
| --- | --- |
| Credential registration and verified PRF recovery | Mandatory platform root and application identity |
| RP/route binding and opaque record encoding | Method selection and authenticated method directory |
| Provider/device interaction and temporary-result cleanup | Purpose-bound derivation, HPKE envelopes and encrypted record frames |
| Advanced counter/backup-state output | Atomic persistence, key rotation, concurrency and recovery policy |

Keybay uses the PRF output as high-entropy input to domain-separated HKDF, not
Argon2. It derives an X25519 recipient key for an RFC 9180 HPKE envelope containing
the store key. The platform protector seals the method package; the manifest
binds the complete package. A recovered store key is provisional until the
manifest authenticates. This is encryption protection, not a UI gate.

On enrollment, Keybay commits the record and envelope with the method change.
On unlock, it verifies the original saved envelope and persists the updated
Keypass verification state before returning a session. Its transaction rejects
conflicting authentication changes. Stable record identity binds derivation;
mutable record state is separately authenticated. Keybay disposes every temporary
Keypass result and clears its own owned derivation buffers.

Adding/removing methods rotates the store key and re-encrypts the records.
Surviving methods are rewrapped using their authenticated public recipient keys,
without retaining their secrets or asking for every credential again. Record
operations and authenticated method listing never prompt or reacquire providers.
A portable hardware credential does not make the platform-bound vault portable.

## Review and release boundary

Review both the [Keypass guide](external-review.md) and
[Keybay guide](https://github.com/danReynolds/keybay/blob/main/doc/external-review.md).
Keybay's checked-in dependency still resolves the published Keypass prerelease;
new Keypass source cleanup is not implicitly used by a Keybay checkout. Record
both source revisions and the actual resolved package/lockfile in joint tests.
A local dependency override is a separate test configuration, not a released
integration. Neither a demo nor the published release constitutes an external
security audit. Current Keybay source rejects the retired V2 singleton-passphrase
format without migration. Published SDK/CLI 0.2.0 artifacts predate that removal
and retain its authenticated conversion path; neither version migrates V1 stores.
Do not apply the current-source compatibility statement to those older artifacts.
