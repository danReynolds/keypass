# Keybay integration

Keybay 0.3.2 consumes Keypass 0.1.0-dev.3. Applications use Keybay's credential
API; Keybay manages the Keypass client, records and temporary results internally.

## Consumer flow

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

For an already protected store, authenticate its current method before adding
another. Await enrollment before writing protected values. Use
`PasskeyCredential.hardware(rpId:, pin:)` for direct hardware; clear caller-owned
PIN bytes after submission. System passkeys require native host/domain setup.

`open(credential:)` authenticates only; enrollment uses `auth.add`. Auth management
is add/list/remove, with at most one passphrase and eight total methods. Removing
the last method leaves platform-only protection. The
[Keybay SDK guide](https://github.com/danReynolds/keybay/blob/main/doc/sdk.md#add-passkey-protection)
covers selection, removal, cancellation and errors.

## Ownership and cryptography

| Keypass | Keybay |
| --- | --- |
| Registration and verified PRF recovery | Mandatory platform root and application identity |
| RP/route binding and verifier-state output | Authenticated directory, method selection and atomic state commits |
| Native interaction and result handoff | Result disposal, derivation, envelopes, rotation and recovery |

Keybay feeds high-entropy PRF material into domain-separated HKDF, deriving an
X25519 recipient key for an HPKE envelope of the store key. The platform protector
seals the package; the manifest authenticates it before a session is returned.
Successful unlock commits advanced verifier state. Add/remove rotates the store
key and rewraps survivors using authenticated public keys, without retaining
their secrets. See [RFC 0003](https://github.com/danReynolds/keybay/blob/main/doc/rfcs/0003-passkey-methods.md)
for the construction and transaction rules.

Protection is `platform AND (passphrase OR passkey A OR ...)`. Removing a method
neither deletes its provider credential nor revokes old snapshots. Credential
portability does not bypass the vault's platform root.

## Review and release boundary

Keybay pins published Keypass; checking out Keypass main does not update that
dependency. Record both revisions and any override in joint tests. Current Keybay
source rejects retired V2 singleton packages; published 0.2.0 retains their
conversion path. Neither migrates V1. Exact baselines and evidence are in the
[Keypass](external-review.md) and
[Keybay](https://github.com/danReynolds/keybay/blob/main/doc/external-review.md) review guides.
