# Consumer SDK

Import `package:keypass/keypass.dart`. Your app owns encryption and persistence;
Keypass owns credential interaction and verified PRF recovery.
[Platform setup](platforms.md) covers native integration.

## Configure the access route once

```dart
final passkeys = Keypass.system(rpId: 'vault.example.com');
final hardware = Keypass.hardware(
  rpId: 'dev.example.vault',
  requestPin: ui.requestPin,
  selectConnection: ui.selectConnection,
  onEvent: ui.onHardwareEvent,
);
```

Construction opens no dialog or device. Clients are reusable configuration and
need no disposal; each operation acquires its own backend.

`rpId` is a stable credential namespace, with many records per RP. A saved record
requires its original route and RP; mismatches fail before device access.
`displayName` is optional presentation text, defaulting to the RP ID.

- **System:** OS providers own the dialog and verification. Apple/Android require
  an associated domain. Windows has no equivalent association enforcement;
  its configured origin does not identify the executable.
- **Hardware:** use a stable DNS-shaped namespace shared by your app/CLI.
  No website is required, but the namespace does not authenticate the caller.

Using the same RP for both routes does not make separate credentials interchangeable.
There are no Keypass API keys or inferred pubspec/environment defaults.

`ui` above is your application. Hardware callbacks are optional:

| Callback | Return/behavior | If omitted |
| --- | --- | --- |
| `requestPin` | Receive `HardwarePinRequest` and cancellation; return owned writable UTF-8 bytes, or `null` to cancel. Keypass clears returned bytes. | Keys needing application PIN input fail with `pinRequired`. |
| `selectConnection` | Return an exact offered `HardwareConnection`, or `null` to cancel. | One connection is automatic; several fail with `deviceSelectionRequired`. |
| `onEvent` | Show `touchRequired` or `presentKey` guidance. | No application progress callback. |

Connections are operation-local USB candidates or NFC readers, not credentials.
Do not reuse one later. Transport hints and a ready reader do not prove key
presence. Close PIN/selection UI on cancellation. PINs are never retried automatically.

## Check readiness without prompting

```dart
final readiness = await passkeys.check();
if (!readiness.canAttempt) {
  // Explain readiness.reason in your UI.
}
```

Optional and prompt-free. It reserves nothing, may throw `busy`, and cannot prove
PRF support or device presence. Operations enforce their own capability checks.

## Create and use a result

```dart
final created = await passkeys.create(label: 'Personal vault');
try {
  // Derive a purpose-bound wrapping key from created.secret.
  // Atomically save created.record.toJson() with an authenticated envelope.
} finally {
  created.dispose();
}
```

Creation registers a credential, generates its public PRF input and verifies two
matching evaluations with fresh challenges. Failure after registration can leave
a provider credential behind; your method is usable only after record/envelope commit.

Both `create` and `unlock` return `PasskeyResult`:

| Member | Meaning |
| --- | --- |
| `secret` | Borrowed read-only 32-byte input for your KDF. |
| `record` | New or updated opaque recovery/verification metadata. |
| `dispose()` | Synchronously and idempotently clears the owned secret buffer. |

Dispose in `finally`. Afterwards the getter throws and borrowed views see zeros.
Copies, derived keys, plaintext and provider/VM allocations need separate cleanup;
complete memory erasure is not guaranteed. Disposal neither saves the record nor
deletes the passkey. The sketches omit your encryption implementation; see the
[executable marker example](../demo/provider_app/lib/store.dart).

## Unlock a saved record

```dart
final record = PasskeyRecord.fromJson(savedRecordJson);
final opened = await passkeys.unlock(record);
try {
  // Authenticate metadata and decrypt the ORIGINAL saved envelope.
  // Atomically persist opened.record.toJson() before exposing a session.
} finally {
  opened.dispose();
}
```

Unlock never enrolls or discovers an arbitrary replacement. Select your saved
method first. The record exposes `id`, `rpId`, `route`, `toJson()` and `fromJson()`;
preserve the entire value. Decoding checks structure, not authenticity.

Your transaction must authenticate metadata and decrypt successfully before
committing the updated record. Handle concurrent updates and clear provisional
plaintext/session keys if commit fails. `record.id` stays stable across counter,
backup-state and USB/NFC changes. Use stable context for wrapping-key derivation
and AAD; mutable record bytes are not immutable identity. The marker example
uses the old record as AAD to decrypt, then re-encrypts with the updated record.

Current records use v2 for system and v3 for hardware; the prerelease format is
not frozen. See [security](../SECURITY.md) for rollback and recovery limits.

## Cancellation and ownership

```dart
final cancellation = PasskeyCancellation();
final pending = passkeys.unlock(record, cancellation: cancellation);
// Connect Cancel to cancellation.cancel().
final result = await pending;
try {
  // Use result.secret and commit result.record.
} finally {
  result.dispose();
}
```

Use a fresh signal per operation. Cancel, await the original Future and dispose
any successful result, even if the initiating screen closes. `Future.timeout`
alone abandons waiting; it neither cancels work nor clears a late secret.

Overlapping work fails with `busy`. Native cleanup precedes success handoff;
cancellation cannot revoke a returned result or undo your subsequent storage
transaction. [Native ownership](../native/OWNERSHIP.md) defines late-callback and
provider-stall behavior.

Catch `PasskeyException.code`: backend/host absence, unsupported PRF, cancellation
and verification failure are distinct redacted errors. Errors/events contain no
raw provider responses, PINs or PRF output.

## Boundary with Keybay

[Keybay](keybay-integration.md) owns derivation, envelopes, authenticated metadata,
platform protection, rotation and atomic storage. It consumes and disposes Keypass
results internally; Keybay applications do not manage these results or records.
