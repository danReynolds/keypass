# Keybay integration target

Keypass provides verified, credential-bound PRF bytes. Keybay continues owning
the vault, platform protector, sessions, authenticated policy, key envelopes,
rotation, migration and recovery. Keypass has no dependency on Keybay.

The current [Keypass consumer SDK](sdk.md) is ready for an integration prototype;
this document remains a target, not an implemented Keybay integration.

Keybay would hold a configured `Keypass.system(rpId:)` or
`Keypass.hardware(rpId:, requestPin:, selectConnection:, onEvent:)` client for
each enabled route. Both expose `check()`, `create(label:)` and `unlock(record)`.
The same RP ID can be configured for both routes; this does not make separately
created credentials interchangeable. Saved records retain their original route
and identity. The clients require no disposal.

For an added method, Keybay calls `create`, derives purpose-bound wrapping
material from `result.secret`, and atomically commits `result.record.toJson()`
with its authenticated envelope and method-directory update. For an existing
method, it decodes the saved `PasskeyRecord`, calls `unlock`, authenticates and
unwraps the original saved envelope, then persists the returned updated record
before publishing the session. Every path disposes `PasskeyResult` in `finally`,
including derivation, verification or storage failures. Keybay separately
clears its own derived keys and temporary plaintext.

`PasskeyRecord.id` is stable across counter/backup-state updates and transport
changes. Use a reviewed stable method ID and context for key-wrapper AAD; do not
bind an immutable envelope to mutable serialized verification state. The whole
record still needs integrity protection in Keybay's authenticated method
directory. Decoding a record does not authenticate it.

Preserve Keybay's credential API:

```dart
// Proposed addition to Keybay; not implemented by this repository.
final session = await Keybay.open(credential: PasskeyCredential());
final method = await session.auth.add(PasskeyCredential(label: 'Personal vault'));
await session.auth.update(PasskeyCredential(methodId: method.id));
await session.auth.remove(method.id);
```

Consumers should not construct a Keypass client merely to use Keybay. Keybay
owns its configured client internally. `PasskeyCredential` is immutable request
metadata; it contains no PRF bytes and presents no UI on construction. Existing
passphrase callers retain their current API.

| Vault state | Explicit open with passkey |
| --- | --- |
| Absent | Enroll, prove PRF, atomically initialize and return session |
| Has passkey method | Unlock the saved record and unwrap its key material |
| Platform-only or another method only | Protection mismatch, without mutation |
| Partial/corrupt/invalidated | Fail closed, without creating over existing state |

Opening without a credential when additional protection is required returns
`AuthRequired` without a provider prompt. Record `get/set/list` operations stay
prompt-free once the session is open. Auth management is explicit.

The intended additional protection is cryptographic: use a reviewed HKDF/context
and authenticated key envelope with PRF output. It is not merely a UI gate.
Keybay's mandatory platform protection remains. A copied vault plus a synced
passkey cannot bypass the original host's required platform root.

Passphrase and passkey are alternative routes unless a separate policy explicitly
requires both. Adding multiple envelopes needs a reviewed format: authenticate
the method directory and wrapping public keys under the vault's own key, rotate
current keys when revoking a method, and reject incompatible old clients. The
investigated per-method public/private wrapping-key design permits rotation
without presenting every other passkey; that design still needs cryptographic
review and vectors before implementation.

Removing a Keybay method and deleting a provider credential are separate actions.
Revocation cannot make already copied old snapshots undecryptable. Provider sync
is not vault portability or independent recovery. Do not cache the PRF secret
in the ordinary platform keystore as a fallback.

Credential snapshots must split by kind: copy and clear passphrase bytes;
snapshot passkey request metadata and asynchronously obtain temporary PRF bytes.
Enrollment failure must leave the existing vault policy intact. Handle a possible
orphan provider credential without quietly replacing a saved unlock route.
