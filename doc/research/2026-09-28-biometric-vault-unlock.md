# Biometric vault unlock investigation

> Research snapshot copied from Keybay. See the [implementation plan](../implementation-plan.md)
> for current Keypass implementation status.

Investigated 2026-09-28 against Keybay commit
`d71eb38b9a78e78a03e9ba4aaf035d48f4a5729a`. This is a design investigation,
not a shipped feature or a qualification receipt for biometric unlocking.

**Direction: build a small Flutter-free biometric-protection package with native
platform implementations, and integrate Keybay as its first consumer.** Native
Swift/Objective-C and Kotlin/Java code are explicitly in scope; exclusively Dart
source is not a requirement. Apple and Android can
enforce authentication at the operation that releases an unlock secret. Linux
fingerprint verification is available, but the standard APIs investigated do not
provide the equivalent protected-key operation. Keep Linux passphrase support;
defer fingerprint-only vault unlocking until a concrete provider can enforce it.

Good Flutter packages exist. None of the candidates inspected is a direct fit
for the standalone Dart CLI, Keybay's exact provider identity, and its explicit
session, failure and reset contracts. This conclusion is about fit; the source
inspection below is not a comprehensive security audit of those packages.

**The security requirement is that authentication controls key access.**
For example, an implementation that calls `local_auth.authenticate()` and then
reads an otherwise accessible secret from the login keyring leaves another
authorized same-user process able to skip that first call. A protected Keychain
item or authentication-bound Keystore operation makes the authentication
requirement part of obtaining the secret itself. An already unlocked Keybay
session still holds a usable store key; biometrics do not protect plaintext
already disclosed or a compromised process after unlocking.

| Platform | Native mechanism | Fit for Keybay |
| --- | --- | --- |
| macOS | Data Protection Keychain item with `SecAccessControl`, authenticated through LocalAuthentication/Touch ID | Yes. CLI signing, provisioning, identity and packaging need explicit work. |
| iOS/iPadOS | Keychain access control with Face ID or Touch ID | Yes. Existing entitled-app profile is a useful starting point. |
| Android | Authentication-bound Android Keystore key plus `BiometricPrompt.CryptoObject` | Yes, using Class 3/strong biometrics. Face recognition qualifies only on devices that meet that strength. |
| Linux desktop | `fprintd` over D-Bus, with libfprint and distro/device support | Verification is possible. Its match result alone does not cryptographically protect a vault secret. |

The Apple mechanisms are documented in [Keychain biometric access][apple-access]
and [macOS Keychain implementations][apple-keychains]. Android documents
[cryptographic biometric authentication][android-guide] and the
[strong-biometric requirement][android-prompt]. Linux exposes verification
through the [fprintd Device API][fprintd].

**Touch ID access on this Mac is available.** A small Swift probe called only
`LAContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` and
inspected `biometryType`. In the user's normal macOS context it returned:

```json
{"biometryType":"touchID","canEvaluateBiometrics":true,"errorCode":0,"errorDomain":"","probe":"capabilityOnlyNoAuthentication"}
```

No authentication prompt was shown, no fingerprint data was obtained, and no
Keychain secret was accessed or changed. The sandboxed first attempt returned
an XPC error (`NSCocoaErrorDomain`, 4099); that was not evidence of unavailable
hardware. The normal-context retry succeeded. This establishes capability only,
not that a packaged Keybay executable can unlock a protected key.

For Apple platforms, store a random method secret in a non-synchronizing,
device-bound Data Protection Keychain item with an access-control requirement.
Request that item during explicit vault opening. Security.framework enforces
the requirement; LocalAuthentication supplies the system interaction. Keybay
does not collect or compare fingerprints or faces. A Secure Enclave private key
could instead protect a wrapped method secret if a non-exportable wrapping-key
design is selected; generic Keychain secret storage must not be described as
such a key.

Choose the authentication policy deliberately. Apple's
[`biometryCurrentSet`][apple-current-set] invalidates access after relevant
enrollment changes. [`userPresence`][apple-presence] also permits the device
credential and survives enrollment changes. An OS password/passcode alternative
is a different policy from a Keybay vault-passphrase alternative. For the first
biometric method, prefer current-enrollment binding and a separately configured
Keybay passphrase recovery route. Cancellation must leave the vault locked;
selecting the passphrase route should be an explicit action.

On iOS, Face ID requires `NSFaceIDUsageDescription` in the host application's
Info.plist. Touch ID does not require a corresponding usage-description key.
The existing app signature, access group and container remain relevant. The
same Apple integration can cover both biometric modalities; the OS supplies
the available modality. [Apple setup and behavior][apple-access]

macOS adds a distribution issue. Apple places biometric-protected Keychain
items in the Data Protection Keychain. Access groups come from the main host
executable's entitlements, authorized by a provisioning profile. A command-line
tool can use an app-like bundle to carry that profile, and must run in a user
login context. This does not inherently require a visible GUI or Flutter.
[Apple's CLI guidance][apple-keychains]

For Keybay, compare two concrete packaging options in the prototype: a properly
signed/provisioned bundled CLI host, or a small signed helper that owns the
biometric item. A helper adds a caller-authentication and IPC boundary and must
not become an unrestricted secret-release service. It is an option, not an
established requirement. Keep the existing signed AOT runtime/module packaging
constraints in view.

Simply adding entitlements to today's CLI is insufficient:
[`MacOSHostPlatform.resolve()`](https://github.com/danReynolds/keybay/blob/d71eb38b9a78e78a03e9ba4aaf035d48f4a5729a/packages/keybay/lib/src/v2/macos_host_platform.dart)
selects a different complete host profile when a signed application identifier
appears. That changes identity/storage commitments. Existing login-Keychain
vaults need a deliberate enrollment/migration design; they must not silently
appear as new empty vaults. The
[macOS platform document](https://github.com/danReynolds/keybay/blob/d71eb38b9a78e78a03e9ba4aaf035d48f4a5729a/doc/platforms/macos.md) records the existing split.

**Android supports the same product behavior through different key APIs.**
Create an authentication-bound AES-GCM Keystore key for the biometric method,
initialize a decryption `Cipher`, and pass that operation to
`BiometricPrompt.CryptoObject`. Consume the authorized operation to recover the
method secret. Request `BIOMETRIC_STRONG`; a device's camera-based face unlock
being available does not establish eligibility for Keystore operations.
[Android API contract][android-prompt]

Prefer authentication for each biometric unlock operation, without a
time-based authorization window inherited from a recent screen unlock.
Explicitly select enrollment invalidation and whether device credentials are
allowed. Android's enrollment invalidation rules are not identical to Apple's:
biometric-only keys normally invalidate on new enrollment or removal of all
biometrics. [Key configuration][android-keygen]

Keybay already requires API 31+, so supporting older Android biometric APIs is
not required for the current SDK. Existing
[`JniAndroidKeystoreAead`](https://github.com/danReynolds/keybay/blob/d71eb38b9a78e78a03e9ba4aaf035d48f4a5729a/packages/keybay/lib/src/v2/android_keystore_protector.dart)
sets `setUserAuthenticationRequired(false)`. Changing that boolean alone would
break operations: the current provider also performs continuity checks and
other cryptographic operations. A separate method key avoids accidentally
requiring multiple prompts for one open. The integration needs host context,
main-thread scheduling, callbacks, cancellation and lifecycle handling. Use
AndroidX Biometric with an Activity-aware adapter where appropriate, or a
bounded framework `BiometricPrompt` bridge at the existing API floor. The
current boot-classpath-only JNI shim does not provide that complete UI bridge.

**Linux needs a separate protection design.** `fprintd` offers device discovery,
enrollment queries, claiming a device, starting verification and receiving a
match status. A Dart integration can use the existing D-Bus dependency. Sensors
and distro versions must be checked against [libfprint support][fprint-devices].

The service does not return a fingerprint-derived encryption key or a
Keychain/Keystore-style protected decrypt operation. The
[Secret Service specification][secret-service] separately leaves additional
access policy to providers. Therefore combining `verify-match` with a normal
Secret Service lookup does not establish the same security boundary. This is
an architectural inference from those interfaces, not a claim that secure
Linux biometric unlocking is impossible.

A Linux implementation would need a trusted broker/provider that owns the
secret and enforces fingerprint authorization itself, potentially with a TPM
design, plus caller identity and distro-specific qualification. TPM presence
alone does not provide that integration. The [current Secret portal][secret-portal]
does not expose a biometric-bound key operation either; Flatpak access to
fprintd would be a separate permission/integration problem. Do not promise a
uniform fingerprint-only unlock feature on Linux based on a prompt plugin.

**The Dart/Flutter library findings are based on current published sources.**
Public pub.dev release metadata and archives were fetched on the investigation
date. Native implementation paths were inspected, not only package feature
lists. Dependencies were not installed into Keybay.

| Candidate inspected | What it actually supplies | Recommendation |
| --- | --- | --- |
| [`local_auth` 3.0.2][local-auth], with Android 2.2.0 and Darwin 2.0.4 implementations | Official Flutter-team authentication/capability plugin; Android, iOS, macOS, Windows; no Linux. Its Dart authentication result is a boolean. | Good for Flutter authentication UI, insufficient as Keybay's key-release boundary. |
| [`flutter_secure_storage` 11.2.0][secure-storage], Darwin 0.4.3 | Actual biometric-protected storage options: Apple access-control flags and Android authentication-bound AES wrapping with `CryptoObject`. | Credible Flutter adapter candidate, but its storage, caching, reset and identity policies need adaptation. Not a standalone Dart dependency. |
| [`biometric_storage` 5.0.1][biometric-storage] | Apple Keychain access control and Android Keystore/CryptoObject; Linux uses libsecret without biometrics. | Relevant implementation reference. Stable release dates to 2024-02-03; 6.0.0-dev.5 was published 2026-08-25, so development is active. Prerelease implementation was not audited here. |
| [`biometric_signature` 13.1.0][biometric-signature] | Native key management, biometric signatures **and decryption** on Apple/Android. Apple EC mode uses Secure Enclave; Android exposes native/hybrid modes. No Linux implementation. | Worth evaluating for a Flutter adapter. Broader crypto and migration surface than Keybay needs; fresh release/API changes require review. It is not merely a signing-only plugin. |
| [`flutter_local_authentication` 2.1.1][flutter-local-authentication] | Adds Linux fingerprint verification. The inspected Linux implementation runs `fprintd-verify` and checks its exit status. | Does not solve protected-key release; its blocking shell-based Linux path also does not fit Keybay's boundary. |

Concrete source observations:

- `local_auth_android`'s `AuthenticationHelper.kt` calls
  `prompt.authenticate(promptInfo)` without a `CryptoObject`; Darwin's
  `LocalAuthPlugin.swift` calls `LAContext.evaluatePolicy`. There is no protected
  secret/key operation exposed by the public `local_auth` API.
- `flutter_secure_storage`'s `AndroidOptions.biometric` defaults to
  `enforceBiometrics: false`, `resetOnError: true`, device-credential fallback,
  and `requireBiometricsPerOperation: false`. Its native implementation caches
  the unlocked storage cipher in that last mode. A Keybay method adapter would
  need explicit enforcement, no automatic destructive reset, an intentional
  fallback policy and fresh authentication across Keybay sessions. Its newer
  per-operation option is relevant if the adapter accesses only the method
  secret at vault opening, leaving record access to Keybay.
- The inspected secure-storage Darwin source uses real `SecAccessControl`.
  However, an access-control creation error returns `nil`, and query building
  has an accessibility-only path for `nil`. That path needs fail-closed review
  before adoption; no exploit or device reproduction is claimed here. It also
  applies the explicitly supplied access group only under `#if os(iOS)`, which
  needs reconciliation with Keybay's explicit macOS group binding.
- `biometric_signature`'s native code implements enrollment-bound access
  control, protected decryption and per-operation Android authorization.
  Choose modes explicitly: some are hybrid software keys wrapped by protected
  hardware keys. The package name or a hardware label is not evidence that
  every key and every operation remains inside secure hardware.

The strongest reusable dependency at the core boundary is likely Dart's
official native interop tooling. [`ffigen` 22.0.0][ffigen] and
[`objective_c` 9.6.0][objective-c] support a Dart-only Apple integration; both
declare Dart >=3.10 and no Flutter SDK requirement. Use the existing Security
C bindings where sufficient, and generated Objective-C bindings or a small
native bridge for `LAContext` and callback/context handling. Generated native
assets and memory/thread lifetimes still need packaging validation.
[Dart's documented interop approach][dart-interop]

The inspected [`jni` 1.0.3][jni] still declares a Flutter environment and Android
plugin, despite `jni_flutter` existing separately. Do not assume today's
published version can replace Keybay's standalone boundary without a packaging
check. An optional Flutter host adapter can take a Flutter dependency without
forcing it into the core SDK or CLI.

**Keybay should own the unlock policy and session lifecycle.** The current
[RFC](https://github.com/danReynolds/keybay/blob/d71eb38b9a78e78a03e9ba4aaf035d48f4a5729a/doc/rfcs/0001-per-application-stores.md) implements platform-only or one
passphrase, and explicitly leaves multiple alternative methods' key rotation
and revocation for a reviewed follow-up. A biometric prompt cannot fill that
cryptographic design gap.

The proposed user policy is platform protection AND (vault passphrase OR a
biometric method on this device). This is an additional unlock route, not MFA.
Protecting the one existing platform root with biometrics instead would make
biometrics required even for the passphrase route. Decide that distinction
before changing the format or provider profile.

Use a random method secret and a reviewed wrapping/rekey design; avoid saving
the user's passphrase as the biometric shortcut. Bind method metadata and
ciphertext to the vault, application identity and method. Closing a session
must discard its unlocked material, and reopening must reacquire authorization.
Explicit opening and method management may prompt; record operations and
diagnostics remain prompt-free. Capability reporting must distinguish missing
hardware, no enrollment, temporary unavailability, cancellation, lockout,
invalidated keys and unsupported execution context.

Suggested implementation order:

1. Establish the small package boundary for capability inspection and protected
   secret/key creation, use and deletion. Implement a disposable signed macOS
   prototype that seals and retrieves one random secret using real biometric
   access control. Compare bundled host and helper packaging, confirm caller
   identity, and prove that reading with interaction forbidden fails. This
   resolves the largest CLI uncertainty while exercising the package contract.
2. Specify alternative-method persistence, removal, key rotation, recovery and
   migration from the current CLI profile. Reuse the existing framed store and
   session model. Do not ship the prototype as a second independent vault.
3. Integrate the macOS method into Keybay as the package's first consumer before
   freezing the public API. Extend the proven contract to iOS and Android with
   one authorized secret-release/decrypt operation per unlock. Keep UI host
   adaptation outside the core storage engine. Do not finish an all-platform
   framework before proving the first complete Keybay interaction.
4. Qualify cancellation, repeated close/open, app backgrounding, OS lock/reboot,
   enrollment changes, credential removal, interrupted enrollment/rotation,
   signed upgrades, restore and missing provider state using disposable vaults
   on real devices. Verify that no unprotected alternate path or persistent
   plugin cache survives the intended lock boundary.
5. Keep Linux passphrases and investigate a concrete protected provider only
   if Linux biometric unlocking becomes a priority. A later FIDO2 hardware-key
   method is a separate cross-platform direction, not an fprintd equivalent.

Only source/API investigation and the non-interactive Mac capability probe
were performed. No biometric decrypt, signed CLI/helper prototype, mobile or
Linux hardware test, vault mutation, dependency change, or production code
change was performed during this investigation.

**Consumer integration and a Flutter-free API.** The intended consumer burden is
native app setup once, followed by common Dart calls. No biometric API key,
cloud account, OAuth client ID, network service or user-supplied encryption key
is needed. Apple signing credentials belong in the build/release pipeline;
they are not runtime SDK configuration.

| Consumer host | Setup the consumer would own | Work the package should own |
| --- | --- | --- |
| iOS/iPadOS app already using Keybay | Existing signing and Keybay's build-expanded `KeybayApplicationIdentifier`; add `NSFaceIDUsageDescription` for Face ID; call enrollment/open and handle session closure. | Keychain access control, OS prompt/context, protected-secret lifecycle, cancellation and typed errors. No biometric-specific entitlement or manually written Swift implementation should be required for this path. |
| Signed macOS GUI app | Valid Data Protection Keychain identity/access entitlements and provisioning; package native assets if the selected binding requires them. | Touch ID interaction and protected-item operations. There is no Touch ID usage-description key analogous to the iOS Face ID key. |
| macOS CLI publisher | Signed/provisioned bundle or qualified helper packaging, plus existing-vault identity continuity/migration. | A supported launcher/helper and the same Dart API. Users installing the finished Keybay CLI should not configure Xcode or entitlements themselves. |
| Android app | `USE_BIOMETRIC` manifest permission, package-provided native bridge integration, and a supported host-context/lifecycle bootstrap if required by the prototype. | Keystore configuration, prompt, crypto callback, main-thread dispatch, cancellation, key invalidation and method-secret handling. Consumers should not implement these callbacks themselves. |
| Linux app | Normal Keybay setup for passphrase access. A future fingerprint backend would need its own supported provider installation. | Report protected biometric unlock as unsupported until that provider exists. Do not silently substitute fingerprint verification for protected unlock. |

On iOS, a private default Keychain access group follows from the app's signed
identity; sharing secrets between apps is a separate capability. Consequently
"turn on Keychain Sharing" should not be advertised as a universal biometric
prerequisite. Keybay's exact-group setup must still match its existing
[iOS requirements](https://github.com/danReynolds/keybay/blob/d71eb38b9a78e78a03e9ba4aaf035d48f4a5729a/doc/platforms/ios.md). [Apple access-group model][apple-groups]

The Android framework `BiometricPrompt.Builder` takes a `Context`; it does not
inherently require the consumer to subclass `FlutterFragmentActivity`. That
particular requirement belongs to some Flutter/AndroidX integration paths.
Keybay has no host Context/Activity registration API today. A framework-based
API-31+ bridge could avoid the Flutter-specific restriction, but native callback
delivery and lifecycle still need implementation. Do not promise permission-only
Android setup before proving the packaging and bootstrap.
[Android builder contract][android-builder]

The clarified distribution requirement is a Dart API and dependency graph with
**no Flutter requirement**. Native platform languages and SDKs are encouraged
underneath that API. Use Swift/Objective-C for Apple integration and Kotlin/Java
for Android where appropriate, with the necessary FFI/JNI transport. The package
owns those bridges; the consumer should not have to write or generate them.
Native asset and Android host integration still need packaging qualification.

For the shared Dart surface, avoid a large `KeybayConfig` containing platform
IDs, access groups, key aliases, native algorithm selections or API secrets.
Keep identity OS-derived. Prompt wording belongs to an operation. Security
choices belong to authenticated method enrollment, where the native key/item
is created; changing an argument on a later read must not weaken an existing
method's requirements.

This is an illustrative future API, **not implemented signatures**:

```dart
// Used to decide whether to offer biometric enrollment; does not prompt.
final availability = await Keybay.biometricAvailability();

// Opt in while the vault is already authenticated.
await session.auth.add(
  const BiometricEnrollment(reason: 'Enable biometric vault unlock'),
);

// Same operation on macOS, iOS and supported Android devices.
final unlocked = await Keybay.open(
  unlock: const BiometricUnlock(reason: 'Unlock your vault'),
);

final value = await unlocked.get('service/token');
await unlocked.close();
```

The existing passphrase credential/open API would need a deliberate compatible
extension or pre-1.0 revision to accommodate these request types. A biometric
request is not captured biometric data. Availability is advisory; opening can
still fail if enrollment or device state changes. Explicit passphrase recovery
remains a separate application choice after cancellation or failure.

The app must decide when to close its vault session, such as on inactivity or
backgrounding. Device authentication does not define that product policy. The
package can supply cancellation and native lifecycle support without imposing
one global UI lifecycle on every Dart host.

A separate Flutter-free biometrics package **does make sense** if its contract
matches what callers need. For Keybay, the reusable unit is a device-local
protected secret/key with capability inspection, creation, authenticated
recovery/use, and deletion. Apple Keychain and Android Keystore implement those
semantics differently, but that is a normal platform abstraction. Keep ordinary
presence verification a distinct capability if it is exposed at all. Linux
`fprintd` can satisfy verification; it cannot satisfy protected-secret release
through its current API alone.

Prefer a name/scope such as biometric protection or device authentication over
a sensor abstraction. A package that additionally supports device PIN/password
authorization should not describe all its operations as biometric-only. Keep
vault passphrases, multi-method policy, record storage, rekeying and session
ownership in Keybay. Build the package first with Keybay as its immediate first
consumer, keeping the initial API provisional until an end-to-end vault unlock
proves the boundary.

**The intended protection is cryptographic access to the encrypted file's key.**
Keybay already encrypts records with a random store key. A passphrase-derived
key protects access to that store key together with platform protection. The
biometric route must likewise require an OS-protected secret or key operation
to recover the store key; it must not merely return `true` and permit a read
that was cryptographically possible beforehand.

On Apple, a biometric access-control item can release the random method secret
only after native authorization. On Android, an authentication-bound Keystore
key authorizes the decrypt operation that recovers that secret. Keybay then
uses the method secret within its reviewed wrapping design to recover the
store key and open the existing encrypted file. No encryption key is derived
from fingerprint or facial measurements, and no biometric templates reach Dart.

The lower package does not encrypt or manage vault records; it supplies the
protected operation needed by Keybay's key management. Bypassing a UI branch
must not recover the missing key material. A copied encrypted file alone must
not become readable through the biometric route. The intended alternative
policy still allows the configured passphrase route when its own requirements,
including baseline platform protection, are met. Neither route protects
plaintext or store keys already available in an authorized open session.

Multiple-method wrapping, enrollment, removal, rotation and recovery still need
their separate Keybay format review. A working biometric package does not by
itself establish the correctness of that design. Linux support must meet the
same protected-key contract before being advertised for vault unlocking.

[apple-access]: https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id
[apple-keychains]: https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains
[apple-current-set]: https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset
[apple-presence]: https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence
[android-guide]: https://developer.android.com/identity/sign-in/biometric-auth
[android-prompt]: https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt
[android-keygen]: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder
[fprintd]: https://fprint.freedesktop.org/fprintd-dev/Device.html
[fprint-devices]: https://fprint.freedesktop.org/supported-devices.html
[secret-service]: https://specifications.freedesktop.org/secret-service/latest-single/
[secret-portal]: https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html
[local-auth]: https://pub.dev/packages/local_auth/versions/3.0.2
[secure-storage]: https://pub.dev/packages/flutter_secure_storage/versions/11.2.0
[biometric-storage]: https://pub.dev/packages/biometric_storage/versions/5.0.1
[biometric-signature]: https://pub.dev/packages/biometric_signature/versions/13.1.0
[flutter-local-authentication]: https://pub.dev/packages/flutter_local_authentication/versions/2.1.1
[ffigen]: https://pub.dev/packages/ffigen/versions/22.0.0
[objective-c]: https://pub.dev/packages/objective_c/versions/9.6.0
[jni]: https://pub.dev/packages/jni/versions/1.0.3
[dart-interop]: https://dart.dev/interop/objective-c-interop
[apple-groups]: https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps
[android-builder]: https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.Builder
