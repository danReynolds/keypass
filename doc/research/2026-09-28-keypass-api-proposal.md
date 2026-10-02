> Historical proposal. The implemented SDK contract is now [doc/sdk.md](../sdk.md).
> Keybay integration remains separate work.

# keypass: proposed Dart API and platform experience

> Research snapshot copied from Keybay. See the [implementation plan](../implementation-plan.md)
> for current Keypass implementation status.

Package name: **keypass**. The package's purpose is to enroll passkeys
and obtain credential-bound PRF secrets for encryption. It has a Flutter-free
Dart API backed by platform SDKs. Keybay is its first consumer.

This is an API proposal, not implemented or published functionality. Package-name
availability is not established. Native support and qualification limits are
recorded in the [platform investigation](2026-09-28-platform-passkey-vault-unlock.md).
Examples below illustrate the intended contract; they are not executable today.

## What opens on the user's device

An explicit enrollment or unlock operation invokes a system credential request
scoped to the consuming application's RP ID. The OS/provider presents its passkey
sheet and verification flow. The user does not need to manually launch their
password manager, find a secret, or copy anything into Keybay.

The dialog is a broker for matching credentials. The underlying passkeys live in
the chosen provider. The package neither obtains a directory of all the user's
passkeys nor reads their private authentication keys.

| Operation | User-visible behavior | Result |
| --- | --- | --- |
| Construct the client | No dialog | Reusable configuration and native host binding |
| Check availability | No dialog | Whether this backend/host can attempt the operation; not a guarantee about an unseen provider's PRF support |
| Enroll | Save/create-passkey sheet, provider/account choice where supported, verification; possibly additional verification to evaluate PRF | Persistable credential binding plus caller-produced ciphertext or other result |
| Unlock | Matching passkey selection/confirmation, then provider verification | Temporary PRF material used by the callback |
| User cancels | System sheet closes | Redacted cancellation/failure, no vault downgrade |
| Close Keybay session | No passkey dialog | Keybay releases its live store key |
| Remove a Keybay method | Keybay changes its authenticated policy and rotates current data keys; platform protection may require UI | New vault state no longer accepts that method; provider credential deletion is separate |

Prompt count and exact wording belong to the OS/provider. A single library
operation may involve more than one native request. The package requires user
verification, while the provider decides whether to use a fingerprint, face,
device passcode or PIN. It must not promise fingerprint-only verification.

## Configure once in the consuming application

The application declares the service domain once. Proposed build configuration:

```yaml
keypass:
  domain: vault.example.com
```

The integration embeds this value for packaged/AOT apps; it does not assume a
runtime pubspec exists. The configuration key and build support are proposed.
This declaration does not itself establish domain ownership or replace Apple's
AASA/entitlement and Android's Digital Asset Links setup.

Standalone package consumers then normally use:

```dart
final passkeys = Keypass();
```

An explicit `domain` override can serve embedders without generated metadata:

```dart
final passkeys = Keypass(domain: 'vault.example.com');
```

### What these settings mean

- **Domain / RP ID:** RP means relying party, the service that owns the credential.
  The RP ID is a stable domain such as `vault.example.com`, without `https://` or
  a path. It scopes which credentials the request can use. It is not a vault
  upload endpoint. An application's package ID is not automatically a valid RP
  domain, and reversing a bundle ID does not establish the required association.
- **Display name:** Human-readable app/service branding. Default it from the
  installed app's declared display name, or its package metadata for CLI hosts.
  Retain an optional override for branding. It is not the security identity.
- **Native host:** Internal execution and presentation context, not a network
  server or a password-manager choice. Remove it from the normal constructor.
  Select the OS backend automatically and resolve presentation context through
  the native integration when the operation begins.

The native integration must still obtain a current Android Activity, an Apple
window/scene presentation anchor, or a Windows owner window. Its bootstrap can
register lifecycle callbacks so Dart applications do not supply these per call.
Use the active context where unambiguous; multi-window and custom embeddings may
need a one-time native presentation callback. A bare CLI/headless isolate has no
Activity or app window to discover. Unsupported or unconfigured runtimes fail
explicitly rather than creating a fake window or launching a browser silently.

Automatic selection removes ordinary caller plumbing, not native packaging,
signing, lifecycle or browser-origin requirements. The exact native bootstrap
contract remains a prototype deliverable, not an already implemented facility.

Each independent application chooses its RP domain. The package may read an
explicit existing declaration, but must not guess among associated domains or
arbitrary manifest URLs. Missing or ambiguous configuration fails before UI.
Apple and Android require domain association with the installed app. No vendor API key or remote
Keybay login service is part of this configuration. A local vault has no intrinsic
need for an email address or remote user account; opaque credential user handles
can be generated locally.

Provider choice normally belongs to the OS/user. Do not expose promises such as
`provider: applePasswords` or `biometric: faceId` as portable selectors. Later
hardware-only policy needs backend enforcement and separate qualification.

## The standalone package

The core contract has two secret-bearing operations: enrollment and evaluation.
Both deliver PRF bytes only inside a callback. Host availability and disposal
complete the lifecycle.

```dart
abstract interface class Keypass {
  factory Keypass({
    String? domain,
    String? displayName,
  }) = _NativeKeypass;

  Future<PasskeyAvailability> availability();

  Future<PasskeyEnrollment<T>> enroll<T>({
    required String label,
    required Uint8List input,
    required FutureOr<T> Function(Uint8List secret) use,
    PasskeyCancellation? cancellation,
  });

  Future<T> withSecret<T>({
    required List<PasskeyBinding> bindings,
    required FutureOr<T> Function(
      PasskeyBinding selected,
      Uint8List secret,
    ) use,
    PasskeyCancellation? cancellation,
  });

  Future<void> dispose();
}
```

The factory defaults identity settings from application metadata and selects
the native implementation automatically. Browser mediation
requires explicit configuration rather than an automatic fallback. Types:

- `PasskeyEnrollment<T>` contains `binding` and `value`. `value` is the callback's
  result, such as an encrypted envelope; it is not a raw PRF secret automatically
  returned by the package.
- `PasskeyBinding` is versioned, serializable, nonsecret metadata: credential ID,
  RP ID, PRF input, public verification material and required interpretation
  parameters. The application must integrity-protect it with its encrypted data.
- `input` is a stable application-supplied PRF input, normally random bytes for a
  new binding. The same binding must retain that input for future evaluation.
- `PasskeyAvailability` reports host/API readiness and known feature limitations.
  It does not enumerate private credentials or promise a compatible provider.
- `PasskeyCancellation` addresses one operation. Disposal cancels/drains the
  client's pending work. Completion is delivered exactly once.

Enrollment creates the credential, checks PRF, and establishes repeatable output
before invoking `use`. If registration only reports extension support, the
implementation makes an assertion request to obtain the output. A second
evaluation confirms reproducibility. Requests require user verification and
validate the returned credential/challenge/RP context. Fresh challenges are
generated internally for this local cryptographic use case.

`withSecret` takes the bindings accepted by this application. One binding makes
the request specific; several let the native UI choose among registered methods.
Backends must map per-credential PRF inputs correctly and report which binding
matched. If a backend cannot implement that selection, it must report the
limitation so the application can explicitly choose a single binding. It must
never show a sequence of speculative prompts or accept an unrelated credential.

Example enrollment:

```dart
final created = await passkeys.enroll(
  label: 'Personal vault on this device',
  input: randomPrfInput,
  use: (secret) => wrapEncryptionKey(secret, encryptionKey),
);

await persistEncryptedEnvelope(
  binding: created.binding,
  envelope: created.value,
);
```

Example reopening, after loading and validating the saved metadata:

```dart
final key = await passkeys.withSecret(
  bindings: [savedBinding],
  use: (selected, secret) => unwrapEncryptionKey(secret, savedEnvelope),
);
```

These `wrap`/`unwrap` functions are application code placeholders for a reviewed
envelope design, including HKDF and authenticated context; they are not proposed
package encryption primitives. The returned `key` is now caller-owned sensitive
material and needs its own bounded lifetime. Keybay supplies that lifetime.

Input buffers are snapshotted before suspension. The package clears its owned
secret buffers in `finally` after the callback settles, including callback
failure. A caller can still copy or leak bytes; callback scoping does not make
that impossible or guarantee erasure of every native/GC/OS copy. Avoid secrets in
base64/JSON public results, logs, exceptions, URLs and diagnostic payloads.

A provider may successfully create a passkey before a later PRF check, caller
callback or disk write fails. The package cannot universally roll that creation
back. Failure must leave the vault policy unchanged and may report nonsecret
orphan-credential metadata for user cleanup. Retrying must not silently replace
an existing enrolled credential.

## Keybay's consumer API

Passkeys use the same credential and auth-manager API as passphrases. Add
`PasskeyCredential` alongside `PassphraseCredential`; do not add separate
passkey-specific open/create/auth-management entry points. Keybay owns its
configured passkey client internally, so consumers do not have to construct or
pass a `Keypass` instance.

```dart
// Existing passphrase API.
final session = await Keybay.open(
  credential: PassphraseCredential(phrase: phraseBytes),
);
```

```dart
// Proposed passkey option, using the same entry point.
final session = await Keybay.open(
  credential: PasskeyCredential(),
);
try {
  final token = await session.get('service-token');
} finally {
  await session.close();
}
```

```dart
// On an already authorized existing session, e.g. opened with a passphrase.
final method = await session.auth.add(
  PasskeyCredential(label: 'Personal vault'),
);

final methods = await session.auth.list(); // Keybay methods; no provider prompt.
final replaced = await session.auth.update(
  PasskeyCredential(methodId: method.id),
);
await session.auth.remove(method.id);     // Explicit policy change and rotation.
```

`PasskeyCredential` is a request to use the configured passkey mechanism. Its
construction is side-effect free; the Keybay operation starts the system request.
It contains optional nonsecret `label` and `methodId` fields, not passkey-private
bytes or a captured Activity/window. `label` is used for enrollment. `methodId`
can restrict opening or identify an existing method to replace.

Match the current `open(credential: ...)` state machine:

| Existing state | `open(credential: PasskeyCredential())` |
| --- | --- |
| Totally absent | Enroll, prove PRF, atomically initialize a passkey-protected store and return `wasInitialized == true` |
| Has an enrolled passkey route | Authenticate that route and open; never create a replacement credential implicitly |
| Platform-only, or protected solely by another method | `ProtectionMismatch`, without mutation; add passkeys through an authorized session |
| Partial, corrupt or invalidated state | Fail closed; do not enroll over existing state |

Supplying a credential remains both an unlock attempt and a requirement that an
existing vault support that method. Calling `open` with a passkey must never
silently enroll it into an existing vault. With no credential, a vault requiring
an additional method returns `AuthRequired` without invoking passkey UI.

`auth.add` explicitly enrolls another passkey. `auth.update` replaces the chosen
passkey atomically, preserving its opaque Keybay method ID; its provider credential
ID changes. With one enrolled passkey the target can be inferred. With multiple,
replacement requires `methodId` and fails before UI if the target is ambiguous.
An add request containing a target method ID is invalid. Removing a method from
Keybay does not promise to delete its credential from provider storage.

On opening, Keybay reads the platform-protected method metadata, submits the
permitted bindings and uses the selected secret to open its key envelope. The
caller never handles PRF bytes, native challenges, salts or wrapped store keys.

Internally, generalize the credential snapshot boundary by credential kind:
passphrases retain their synchronous owned-byte snapshot and cleanup rules;
passkeys snapshot immutable request metadata and acquire temporary secret bytes
asynchronously through the native provider. Do not model a passkey request as
already available secret bytes. Provider injection belongs at the engine/native
integration boundary, not in every normal credential constructor.

Creating a passkey-only vault commits only after successful enrollment. Existing
vault enrollment commits atomically after confirmation and concurrency checks.
Adding a passkey does not remove a passphrase. Removing the last additional method
is a deliberate return to platform-only protection and must be described as such
by the consuming UI. A passkey alternative does not imply passphrase-plus-passkey
MFA. Ordinary record operations never invoke a credential provider.

## Native backends and visible UI

| Runtime | What the adapter invokes | What the user sees | Packaging/setup |
| --- | --- | --- | --- |
| iOS / iPadOS | AuthenticationServices platform credential create/get with PRF | System passkey sheet, then Face ID/Touch ID/passcode or provider verification | iOS 18+ PRF API; Swift/Objective-C bridge, presentation anchor, signed app plus associated domain/AASA |
| macOS app | AuthenticationServices platform credential create/get with PRF | System passkey sheet and Touch ID or other accepted verification; credential lives in Apple Passwords or a compatible configured provider | macOS 15+ PRF API; AppKit host/presentation plus signing and associated domain/AASA |
| Android | Jetpack Credential Manager create/get with PRF extension JSON | Credential Manager sheet for provider/account selection and provider verification | JNI bridge, Gradle libraries, Activity lifecycle and Digital Asset Links; qualify actual provider PRF support |
| Windows | WebAuthn OS functions with PRF inputs/outputs | Windows credential/security UI with available methods, potentially Windows Hello, phone or security key | FFI/C bridge, window ownership and version/provider qualification; Keybay storage backend still needed |
| Linux browser backend, proposed | Browser WebAuthn through an explicitly configured bridge | Browser passkey picker/provider prompt, potentially using Google Password Manager, a phone or an extension | Separate origin, IPC and distribution design; not a native Linux dialog or an implemented backend |
| Linux native portal, future | A qualified credential portal backend | Portal/provider-controlled UI | Current reference project remains experimental; do not claim distro-wide support |

OS/provider selection options do not imply that every offered route returns PRF.
The package must require a successful PRF evaluation rather than relying on the
visual appearance of the dialog. A native callback reports cancellation/failure
without exposing raw provider messages or silently falling back to a password.

A standalone macOS CLI also needs a signed/presentable host or reviewed browser
route. A pure Dart API does not remove these OS requirements. The package must
report missing host setup rather than inventing a temporary invisible window.

## Storage and failure boundaries

| Location | Contents |
| --- | --- |
| User's passkey provider | The credential's private authentication and PRF material; provider handles access, storage and optional sync |
| Keybay file | Encrypted records, encrypted key envelopes and authenticated credential references/inputs |
| Existing platform keystore | Keybay's mandatory platform root/sealing capability |
| Process memory | PRF bytes during the operation; recovered Keybay store key during the session |

Use stable errors for unsupported backend, unconfigured host, rejected domain
association, unavailable credential/provider, absent PRF output, timeout/busy,
user cancellation and failed verification. Only distinguish causes that the
platform actually reports; some APIs deliberately conflate cancellation and
missing credentials. None of these failures unlocks or weakens the vault.

The library supplies no remote accounts or synchronization service. Provider sync
and Keybay vault portability remain separate. Offline availability is a measured
property of the selected provider/path. Removing a local method does not promise
to delete the credential from every synced provider device.

## Primary UI references

- [Apple modal passkey sheets and credential allow lists](https://developer.apple.com/videos/play/wwdc2022/10092/)
- [Android create-passkey flow and Credential Manager sheet](https://developer.android.com/identity/passkeys/create-passkeys)
- [Android sign-in flow](https://developer.android.com/identity/passkeys/sign-in-with-passkeys)
- [Windows passkey experience](https://learn.microsoft.com/en-us/windows/security/identity-protection/passkeys/)
- [PRF semantics](https://www.w3.org/TR/webauthn-3/#prf-extension)
- [RP ID and app association](https://web.dev/articles/webauthn-rp-id)

The UI descriptions above are documented platform behavior, not screenshots or
live enrollment evidence from this investigation. The API is an implementable
design target; it still needs native-host and cryptographic-format review.
