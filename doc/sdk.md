# Consumer SDK

Keypass obtains verified, repeatable passkey-derived material for a consumer's
encryption scheme. The public import is `package:keypass/keypass.dart`.
It has no Flutter dependency. [Platform setup](platforms.md) covers native
packaging, signing, permissions and domain associations; this page owns the Dart
API contract.

## Configure the access route once

```dart
final passkeys = Keypass.system(
  rpId: 'vault.example.com',
  displayName: 'Example App',
);

final securityKeys = Keypass.hardware(
  rpId: 'vault.example.com',
  displayName: 'Example App',
  requestPin: ui.requestPin,
  selectConnection: ui.selectConnection,
  onEvent: ui.onHardwareEvent,
);
```

Both constructors return the same `Keypass` interface. Construction opens no
device or dialog. Clients contain configuration and can be reused; there is no
client `dispose()`. Each operation acquires and releases its own native backend
and connection selection before returning.

`rpId` is the stable relying-party identifier that scopes credentials:

- `Keypass.system` uses OS passkey providers and their dialogs. Use your
  associated domain and complete the platform's app/domain setup.
- `Keypass.hardware` talks directly to physical FIDO2 keys. Use a stable
  DNS-shaped identifier shared by your app and CLI, such as `dev.example.vault`.
  It requires no hosted website or domain association. It does not authenticate
  the requesting executable.

The same RP ID can be used for both routes, as above. This does not make
separately created credentials interchangeable. A record can only be unlocked
through a client with its original route and RP ID; a mismatch fails before device
access. Existing credentials with different RP IDs retain their original IDs.
Do not derive the RP ID from a changing package name, app label or build flavor.
Display name is presentation text and defaults to the RP ID. There are no Keypass
API keys, accounts, or implicit pubspec/environment configuration.

`ui` above is the consuming application's UI, not an SDK object. Hardware
handlers are optional parameters with explicit behavior:

| Handler | Contract when supplied | When omitted |
| --- | --- | --- |
| `requestPin` | Receive `HardwarePinRequest` and cancellation; return owned writable UTF-8 bytes, or `null` to cancel. Keypass clears the returned bytes. | A key requiring application PIN entry fails with `pinRequired`. |
| `selectConnection` | Receive the offered `HardwareConnection` objects and cancellation; return one of those exact objects, or `null`. | One connection is selected automatically; multiple choices fail with `deviceSelectionRequired`. |
| `onEvent` | Show informational `touchRequired` or `presentKey` instructions. | No application progress callback. |

A connection is a USB candidate or NFC reader, not an enrolled credential.
Its optional `transport` is a hint; a ready NFC reader does not prove a key is
present. Never retain a selected object for a later operation. Close selection
and PIN dialogs on the supplied cancellation signal. Keypass does not automatically
retry PINs, reset keys, or silently substitute another credential.

OS provider dialogs own provider selection and user verification. The system
constructor takes no PIN or biometric hooks, and Keypass does not read biometric
data.

## Check readiness without prompting

```dart
final readiness = await passkeys.check();
if (!readiness.canAttempt) {
  // Present readiness.reason to explain why access cannot be attempted.
}
```

`PasskeyReadiness` answers whether the configured host can attempt an operation.
It does not promise that a selected credential/provider supports PRF or that a
physical key is currently present. Calls still enforce readiness and capability
requirements internally. Readiness is optional and reserves no native operation
or device. It can throw
`busy` if another operation is active. It is a UI aid, not a prerequisite or
authorization.

## Create and use a result

```dart
final created = await passkeys.create(label: 'Personal vault');
try {
  // Derive a purpose-bound wrapping key from created.secret.
  // Atomically persist created.record.toJson() with an authenticated envelope.
  // Clear application-owned derived keys and plaintext in their own finally.
} finally {
  created.dispose();
}
```

Encryption and persistence are application responsibilities. The comments above
mark that work; they are not a complete encryption implementation. See the
[executable encrypted-marker example](../demo/provider_app/lib/store.dart).
Creation registers a credential and verifies two matching PRF evaluations with
fresh challenges. Keypass generates and retains the original public PRF input.
A failed operation after registration may leave a credential in the provider;
no successful encryption method has been committed unless the application saves
its record and envelope.

Both `create` and `unlock` return `PasskeyResult`:

- `secret`: a borrowed, read-only 32-byte view for the application's
  purpose-bound KDF. It is input key material, not a complete encryption format.
- `record`: the new or updated opaque recovery metadata.
- `dispose()`: synchronous, idempotent clearing of the result's owned secret
  buffer. It neither removes the passkey nor saves the record.

Always dispose the result in `finally`, including when derivation or storage
fails. After disposal, the secret getter throws and earlier borrowed views
observe zeros. Caller copies and derived keys require their own cleanup; Dart,
OS and provider allocations prevent a promise of complete memory erasure.

## Unlock a saved record

```dart
// savedRecordJson is the record persisted by the consuming application.
final record = PasskeyRecord.fromJson(savedRecordJson);

final opened = await passkeys.unlock(record);
try {
  // Derive wrapping material from opened.secret.
  // Authenticate saved metadata and decrypt the ORIGINAL saved envelope.
  // Atomically persist opened.record.toJson() before publishing a session.
  // Clear application-owned derived keys and plaintext on every path.
} finally {
  opened.dispose();
}
```

The application must authenticate its stored method metadata and successfully
decrypt before committing the updated record or returning a usable session.
The application's persistence operation must provide the required
transaction/concurrency semantics; the sketch does not supply a vault
implementation. Application-owned plaintext or session keys must also be cleared
if a later commit fails.

`PasskeyRecord` exposes `id`, `rpId`, `route`,
`toJson()` and `fromJson()`. Keypass owns the schema, PRF input and
verification state. Decoding validates structure, not authenticity. Preserve the
whole record and integrity-protect it with the corresponding method directory.
Persist the result's updated record after each successful unlock.

`record.id` stays stable across verification-state updates and USB/NFC
transport changes. Use a reviewed stable identity/context for key-wrapper AAD
and purpose binding; do not accidentally use mutable record bytes as immutable
AAD. The qualification demo intentionally authenticates its entire saved record:
it decrypts using the **original** saved JSON, then re-encrypts using the advanced
record. See its [complete store example](../demo/provider_app/lib/store.dart).

The current serializer retains the development v2 system and v3 hardware record
encodings, including legacy wire field names. This unpublished package's storage
format is not yet frozen. Unlock never enrolls, replaces, discovers arbitrary
credentials, or changes access routes. Applications choose the saved method first.

## Cancellation and ownership

**Do not abandon a secret-bearing Future.** `Future.timeout` only stops waiting;
it does not cancel the underlying operation or clear a result that completes
later. Cancel the supplied `PasskeyCancellation`, await the original Future's
settlement, and dispose any successful result. Keep this cleanup running even
when the initiating UI closes. A timer may request cancellation; it must not
replace awaiting the operation.

```dart
final cancellation = PasskeyCancellation();
final pending = securityKeys.unlock(
  record,
  cancellation: cancellation,
);
// Connect a Cancel control to cancellation.cancel().
final result = await pending;
try {
  // Use result.secret and result.record in the consumer's encryption flow.
} finally {
  result.dispose();
}
```

Use a new cancellation signal per operation. An overlapping operation fails with
`busy` rather than replacing or silently queueing another operation. Native
work is drained before success transfers ownership of a result. Later
cancellation cannot revoke a result already returned to the caller. The
application controls its subsequent encryption and persistence transaction.

Errors expose stable redacted `PasskeyException.code` values. Missing host
libraries, missing presentation hosts, unsupported PRF, cancellation and failed
verification remain distinct. Neither errors nor progress events carry raw
provider responses, PINs or PRF output.

## Boundary with Keybay

Keypass owns credential creation, verified secret recovery, native interaction
and temporary-result cleanup. Keybay owns purpose-bound derivation, encrypted
key envelopes, authenticated method metadata, mandatory platform protection,
atomic method changes, rotation and recovery. A working Keypass demo is not a
Keybay integration claim. See the [integration target](keybay-integration.md).
