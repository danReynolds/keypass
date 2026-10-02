# Platform-stored passkeys for Keybay vault unlock

> Research snapshot copied from Keybay. See the [implementation plan](../implementation-plan.md)
> for current Keypass implementation status.

Investigated 2026-09-28 against
`d71eb38b9a78e78a03e9ba4aaf035d48f4a5729a`.

This is an implementation proposal supported by native API, published package,
and current Keybay source inspection. A small Apple PRF request probe passed
Swift type checking on this Mac (macOS 26.2). No credential was created or used,
no biometric prompt was presented, and no real-provider round trip, sync,
offline behavior, or vault migration was tested. No production code or dependency
was changed. The earlier [hardware-key investigation](2026-09-28-fido2-vault-unlock.md)
remains relevant, but platform-stored passkeys use different native backends.

## Recommendation

Support **PRF-capable passkeys as an additional cryptographic unlock method**.
The user can create a passkey in Apple Passwords, Google Password Manager, or
another compatible provider, then use its normal system prompt to open Keybay
without typing a Keybay passphrase. Provider PIN/device-password fallback may
still appear; this is not a promise of biometric-only access.

Build a small Flutter-free Dart credential-secret package with native adapters.
Keybay should retain ownership of its encrypted format, unlock policies,
sessions, and migrations. Corbado's Flutter `passkeys` package is a useful
implementation reference, but not a direct dependency for the Dart-only SDK.

Prioritize native Apple and Android integration. Treat Windows provider support
as an explicit qualification target and Linux platform-storage access as a
separate browser/portal integration decision. A common Dart contract is feasible;
zero-setup access to every password manager from every native process is not.

## What the user would experience

1. Open an existing vault through its current protection, then choose Add passkey.
2. The system lets the user select a compatible passkey provider and authorize
   creation. Keybay creates an app-specific credential with a recognizable vault
   label. It does not reuse the passkey for the user's Google or Apple account.
3. Prove that the credential returns usable PRF output, and confirm a repeat
   evaluation before committing the new unlock method. Creation can succeed
   while PRF is unavailable; that must not activate the method.
4. Subsequent explicit vault opens select the registered credential and display
   the provider's verification UI. Keybay uses the PRF result to recover its key.
5. Record reads/writes remain prompt-free inside the open session.

The SDK should not require a password as a precondition for a new passkey-only
vault. Initial enrollment must finish before committing that vault; cancellation
must never leave an unintended platform-only vault. For existing vaults, adding
a passkey retains the passphrase until an explicit removal. Passphrase recovery
is optional policy, not an unavoidable second prompt.

Passkeys are scoped to an RP ID, generally a domain. The consuming application's
identity and domain must be associated. Each independent Keybay consumer should
own its RP identity; sharing one universal Keybay RP across unrelated apps would
create unwanted credential sharing and centralize onboarding. [RP ID rules][rp-id]

## Cryptographic fit

Current Keybay stores the platform-sealed key package in the encrypted file.
The platform root does not store a plaintext passphrase-unlocked `Kstore`.
With a passphrase configured, Argon2id derives the inner wrapping key.
See [the current RFC](https://github.com/danReynolds/keybay/blob/d71eb38b9a78e78a03e9ba4aaf035d48f4a5729a/doc/rfcs/0001-per-application-stores.md#additional-unlock-methods).

Conceptually, a single passkey route becomes:

```text
secret  = PRF(registered credential, stored random input)
Kwrap   = HKDF(secret, purpose and vault/method context)
inner   = authenticated encryption of Kstore under Kwrap
package = platform seal(inner + authoritative policy)
```

This is real protection of the store key. Possessing the file and ordinary
platform root alone does not supply the PRF secret. Security additionally depends
on how the chosen passkey provider protects and releases that secret. A synced
passkey is not the same isolation boundary as a removable hardware key.

PRF output already has cryptographic entropy; it does not need Argon2's password
guessing cost. HKDF supplies domain separation. The PRF result is separate from
the passkey's authentication signature. Do not derive keys from signatures or
silently replace missing PRF with an authentication-success boolean. [PRF standard][prf]

The diagram is a single-route explanation, **not the proposed multi-route wire
format**. The existing RFC requires a reviewed rotation/revocation design before
multiple methods can ship.

### Rotation while retaining other methods

Bitwarden provides a useful design precedent: generate a separate encryption
key pair per method, protect its private key with the PRF-derived key, and wrap
the account key with its public key. Rotation can then use retained public keys
without evaluating every enrolled passkey. Its implementation uses RSA; Keybay
should review a standard public-key envelope construction before choosing its
own primitive and encoding. [Bitwarden design][bitwarden]

For Keybay, investigate this structure for passphrase, passkey and future recovery
routes together:

- Each method has a public wrapping key and an encrypted private unwrapping key.
  PRF or Argon2 protects that private key.
- The current `Kstore` is separately wrapped for each authorized method.
- The entire package remains protected by the mandatory platform protector.
- Bind the method directory and public wrapping keys to authenticated state
  verified using `Kstore`, not just the platform root. An attacker who knows the
  Linux platform root must not substitute a public wrapping key that receives
  the next rotated `Kstore`.
- Bind the private-key envelope to stable store/method/credential/algorithm
  context. Bind the wrapped store key to the changing epoch. Making every private
  envelope depend on the changing epoch would require all credentials again.
- Removing a method rotates `Kstore` and re-encrypts current records, preserving
  the remaining routes. Previously captured snapshots remain decryptable with
  the credentials valid for those snapshots; revocation cannot erase old copies.

The required policy is `platform AND (passkey A OR passkey B OR passphrase)` when
those methods are configured. This is not implicit multifactor authentication.
No hidden platform-only copy of `Kstore` may remain as a convenience fallback.

## Platform and consumer setup

| Platform | Native access to provider-held passkeys | Consumer integration and qualification |
| --- | --- | --- |
| iOS / iPadOS | AuthenticationServices platform credential requests expose PRF on iOS/iPadOS 18+. Apple Passwords is the first target; third-party providers require separate PRF verification. | Swift/Objective-C bridge, app presentation anchor and lifecycle, associated-domain entitlement, signing/provisioning, and AASA `webcredentials` entry for the app. |
| macOS app | The same platform-credential PRF APIs are available on macOS 15+. | Signed app identity, associated domain/AASA, and AppKit presentation/event-loop integration. A Dart FFI binding alone does not provide that host context. |
| macOS standalone CLI | Cannot assume a bare `dart run` process has the app identity and presentation context required by AuthenticationServices. | Qualify a signed application/helper with authenticated IPC, or use a separately reviewed browser route. A generic helper must not grant unrelated callers access to another app's RP. |
| Android | Jetpack Credential Manager carries PRF extension JSON through native create/get requests to the selected provider. Google Password Manager is the first target. | Java/Kotlin bridge through JNI, Gradle dependencies, live Activity and cancellation/lifecycle handling, and hosted Digital Asset Links naming the package and signing certificates. Passkeys have an Android 9 API floor; alternative providers become selectable on Android 14+. These are not universal PRF guarantees or a change to Keybay's existing Android floor. |
| Windows | `webauthn.dll` exposes PRF/hmac-secret inputs and outputs, and system credential UI. | Dart FFI/C adapter, window ownership, cancellation and runtime API-version checks. Qualify the actual Windows build and provider through create plus repeated get; API support alone does not certify Windows Hello or every installed provider. Keybay's Windows storage protector is also still unimplemented. |
| Linux | Chrome can use Google Password Manager, but that is a browser facility. The native `credentialsd` effort remains a proposal/reference implementation with experimental integrations. | A browser bridge is a possible provider-storage route. A native portal backend needs its own compatibility and distribution qualification. Direct libfido2 supports external keys, not reading Apple/Google password-manager stores. Do not claim universal native Linux platform-passkey support. |

Sources: [Apple PRF updates][apple-updates], [Apple platform request][apple-prf],
[Apple domain setup][apple-setup], [Android setup][android-setup],
[Google environment support][google-environments], [Windows API][windows-header],
[Linux reference implementation][linux-credentials].

The Apple platform-passkey version floor above differs from the newer Apple
physical-security-key PRF APIs discussed in the hardware-key report.

### Configuration can stay small, but deployment cannot be invisible

Declare the stable RP domain once in application configuration. Default the
display name from app metadata, and select the native backend automatically.
Presentation context belongs in native lifecycle integration, with advanced
callbacks where needed, rather than a required public `host` argument. Enrollment
can accept a friendly credential label; generate opaque user handles locally
rather than requiring an email or a Keybay account. Avoid accidental credential
replacement when several device-local vaults use the same provider and RP.

Keybay owns credential identifiers, salts/PRF inputs, derivation versions,
authenticated method metadata and envelopes. Consumer applications should not
manage PRF bytes, KDF parameters, or store keys.

No vendor API key, OAuth client secret, paid authentication service, or Keybay
account backend is intrinsic to this local design. The application can generate
challenges and verify ceremony responses locally. The mobile domain association
files are public static deployment metadata. The passkey provider may require
its own user account, connectivity, and recovery setup.

The proposed application-facing API adds `PasskeyCredential` to the existing
`Keybay.open(credential: ...)` and `session.auth.add/update/remove/list` flow.
Absent-state opening enrolls and initializes, matching passphrase semantics;
existing-state opening only uses an already configured method. See the
[API proposal](2026-09-28-keypass-api-proposal.md). Internally, today's
credential snapshot boundary needs distinct handling for passphrase bytes and
passkey request metadata. An asynchronous native operation descriptor must not
pretend to be already available secret bytes or retain a stale Activity/window.

## Package reuse and implementation boundary

The previously downloaded published Corbado sources were inspected again:

- `passkeys` 2.23.1 provides the broad Flutter API and documents PRF support.
- `passkeys_darwin` 0.4.5 sets PRF on platform registration/assertion requests and
  reads the returned symmetric result. This is directly relevant to this proposal.
- `passkeys_android` 2.14.1 inserts `extensions.prf.eval.first` into Credential
  Manager request JSON and reads `clientExtensionResults.prf` from responses.
- `passkeys_windows` 0.1.5 is a useful reference for native PRF fields and UI.
- The package does not provide Linux. Its Flutter lifecycle/method-channel
  integration cannot be imported into Keybay's standalone Dart runtime.

Use these as reviewed integration references, respecting their licenses. Keep
the operating-system SDKs as the native foundation. There is no demonstrated
drop-in Flutter-free Dart package covering the whole provider-storage matrix.
[Published passkeys package][dart-passkeys]

Our narrow package should support credential enrollment, PRF evaluation,
operation cancellation and typed errors. Share that semantic contract with a
future external-security-key adapter; do not call it a biometrics package.
Avoid building account login, vault storage, or passkey-provider software into it.

Capability probes can report API availability, but actual enrollment/evaluation
must establish credential support. Internally keep secret outputs in scoped
owned buffers, redact diagnostics, and minimize copies. Flutter peers serialize
PRF data as base64 strings; Keybay should not inherit long-lived immutable secret
strings at its public API. Native and Dart cleanup remain best effort, not an
absolute promise about allocator, OS, or crash-dump copies.

## Cross-platform and recovery limits

**A provider's sync is not universal provider interchange.** Apple and Google
can each make credentials available in multiple environments, but their stores
do not become one store. A third-party provider or phone-based authentication
can bridge some environments. Test PRF output equality for every supported
native/browser/synced/hybrid path, not merely successful login. Provider migration
must preserve the PRF secret as well as signing material; otherwise enroll a new
method through an already authorized session.

**Passkey sync does not migrate a Keybay vault.** The existing platform root and
host binding remain mandatory. A copied vault plus synced passkey still cannot
open on a machine lacking that platform root. Portable encrypted exports or
cross-device vault sync would need a separate design, just as with passphrases.

**Local storage does not imply offline provider availability.** Chromium's
current enclave authenticator uses network transactions for credential
operations; Google's original desktop design also explicitly described a remote
key-wrapping service. Do not assume Google Password Manager desktop behaves like
a locally available hardware key. Test cold/warm offline opens per provider.
[Chromium implementation][chromium-enclave], [Google design note][gpm-design]

**Recovery must remain cryptographic.** Allow a passphrase, another independently
enrolled credential, or a separately designed random recovery-key route. Two
devices with the same synced passkey are not independent recovery methods. Losing
all configured methods means losing access; losing the mandatory platform root
also remains fatal under the current format. Never cache PRF output in the
ordinary keystore to bypass provider failure.

**Removing a method and deleting a provider credential are different.** Removing
the Keybay route revokes it for the new vault state. It need not erase the
passkey from Apple/Google storage; provider management UI or supported signaling
handles that separately. Deleting the only provider credential can lock the user
out even though the encrypted vault file remains intact.

### Linux/browser decision

A browser helper could reach Linux passkey providers, but it is additional
security-sensitive product work. A localhost origin cannot casually claim the
production RP ID. A hosted HTTPS helper has an origin matching the RP but brings
website-code integrity and online availability into the unlock boundary. An
extension is another packaging and permission model. [Origin restrictions][rp-id]

Any bridge must bind requests and replies to the originating application,
operation and vault, authenticate local IPC, and prevent replay or cross-app
confusion. Do not put PRF secrets in URLs, redirects, browser history or logs.
Encrypting a return channel does not protect against compromised helper JavaScript
that already receives the secret. Investigate this as a deliberate backend,
not a transparent consequence of opening a browser tab.

## Proof plan and effort

First build a disposable native host demonstration before committing a public
API or changing production vaults:

1. Apple app on this Mac plus iPhone: create a PRF-enabled platform passkey, repeat
   evaluation after process restart, and compare outputs across the intended sync
   path without printing or persisting secret outputs.
2. Android native host with Credential Manager and Google Password Manager:
   repeat the same exercise, then test one third-party provider and unsupported
   PRF behavior. Verify domain association with debug and release signing.
3. Windows: prove the chosen provider returns a repeatable result on supported
   builds. Linux: decide whether browser mediation is an acceptable consumer and
   trust model before promising native platform-storage support.
4. Exercise user cancellation, missing/deleted credential, biometric lockout and
   PIN fallback, provider outage, process restart, and cold/warm offline operation.
5. Only then implement a reviewed format migration with authenticated method
   directory, passphrase/passkey alternatives, removal, full-key rotation,
   concurrency and interrupted-write tests. Confirm old clients reject the new
   format rather than misinterpreting it.

Planning ranges for one experienced Dart/native engineer with devices and an
associated domain available: approximately one engineer-week for a bounded
feasibility pass; roughly 4–6 weeks for Apple/Android adapters plus Keybay format,
recovery, migration and consumer flows; approximately 8–12 weeks for broader
Windows/Linux coverage if a browser bridge is included. These are estimates,
not measured implementation effort. Windows's unfinished Keybay protector,
security review scheduling and unresolved Linux distribution choices can add
time. A native package that merely returns PRF bytes is a much smaller deliverable
than this complete vault feature.

## Local evidence

- Inspected current `keybay_v2.dart`, `framed_store_rotation.dart`,
  `format/store_crypto.dart`, the RFC and existing research notes.
- Current production runtime supports Android, iOS, Linux and macOS; other
  platforms use `UnsupportedHostPlatform`.
- No existing passkey domain-association configuration was found in the searched
  app/package entitlements, plists, XML or JSON.
- Installed AuthenticationServices SDK declares platform PRF at macOS 15/iOS 18.
- `swiftc -typecheck` succeeded for registration with `.checkForSupport`,
  assertion with `.inputValues`, required user verification, credential filtering,
  and the returned symmetric key API. Probe:
  `/private/tmp/keybay-passkey-research-20260928/platform_prf_typecheck.swift`.
  This confirms API compilation only, not signed-host or live-passkey behavior.

[prf]: https://www.w3.org/TR/webauthn-3/#prf-extension
[rp-id]: https://web.dev/articles/webauthn-rp-id
[bitwarden]: https://contributing.bitwarden.com/architecture/deep-dives/passkeys/implementations/relying-party/prf/
[apple-updates]: https://developer.apple.com/documentation/updates/authenticationservices
[apple-prf]: https://developer.apple.com/documentation/authenticationservices/asauthorizationplatformpublickeycredentialassertionrequest/prf-60tle
[apple-setup]: https://developer.apple.com/documentation/authenticationservices/connecting-to-a-service-with-passkeys
[android-setup]: https://developer.android.com/identity/credential-manager/prerequisites
[google-environments]: https://developers.google.com/identity/passkeys/supported-environments
[windows-header]: https://github.com/microsoft/webauthn/blob/master/webauthn.h
[linux-credentials]: https://github.com/linux-credentials/credentialsd
[dart-passkeys]: https://pub.dev/packages/passkeys/versions/2.23.1
[chromium-enclave]: https://raw.githubusercontent.com/chromium/chromium/main/device/fido/enclave/enclave_authenticator.cc
[gpm-design]: https://lists.w3.org/Archives/Public/public-webauthn-adoption/2024Jul/0002.html
