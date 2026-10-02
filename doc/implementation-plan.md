# Implementation plan

## Accepted scope — 2026-09-29

Keypass is a Flutter-free Dart library for credential-bound encryption secrets.
Its accepted scope has two access routes through one enrollment/evaluation contract:

- OS credential providers in supported native app hosts: Apple
  AuthenticationServices, Android Credential Manager, and the existing Windows
  WebAuthn adapter when its provider/OS combination is qualified.
- Physical FIDO2 security keys on iOS, Android, macOS, Windows and Linux.
  Desktop CLI access uses hardware keys. USB and phone NFC are in scope;
  desktop NFC requires separately qualified readers and drivers.

Physical hardware support is vendor-neutral and capability-based. Yubico SDKs
are implementation dependencies, not a reason for per-vendor adapters or brand
allowlists. Other manufacturers need qualification before support is claimed.

Both routes must return verified, repeatable PRF material. A passkey login or
biometric-success boolean is insufficient. OTP, PIV and general security-key
administration are outside scope. Keybay continues to own encryption envelopes,
the platform root, storage, migration and recovery.

Browser-assisted CLI access and an extension/companion are deferred. Preserve
the existing browser probe and its evidence as research; neither is a required
release backend. This supersedes the earlier browser-first CLI recommendation.

A supported-platform claim requires an actual packaged consumer and real
credential enrollment, restart and decryption. API availability, compilation,
emulator smoke tests and synthetic PRF fixtures are separate evidence. Exact
executed checks live in [validation](validation.md); setup and the target matrix
live in [platforms](platforms.md).

## SDK boundary accepted and implemented — 2026-10-02

The current consumer contract is [SDK usage](sdk.md): synchronous
`Keypass.system(rpId:)` and `Keypass.hardware(rpId:, requestPin:,
selectConnection:, onEvent:)` configuration, `check()`, imperative `create/unlock`,
opaque records and explicitly disposed results. Backends and device selection
belong to operations; no client session is opened. Callers provide the RP ID once,
without ambient domain/namespace defaults. v2/v3 record bytes and inputs survive.

This SDK completion does not complete Keybay envelope integration or broaden the
physical platform qualification matrix. Manual native host packaging remains
documented; automated native dependency distribution is a separate release task.

## Runtime independence constraint

Enrollment, PRF evaluation and recovery must not depend on a Keypass-operated
website, API, relay, account service, domain-association service or online app
registry. Keypass ships software and its security updates.

The OS-provider route uses the consumer's domain and required app associations.
The direct hardware route uses a stable credential namespace and native device
access; no public hosting or domain verification service is required. A namespace
is not proof of which local executable made the request. An OS-mediated hardware
route follows that OS API's identity and presentation rules.

The user's chosen credential provider may require its own account/network.
Qualification must establish that no Keypass-operated endpoint is needed.
The existing Firebase association deployment is an isolated native-demo fixture,
never an SDK default or consumer service. Browser research does not alter this
constraint.

## 0. Existing foundation

- [x] Standalone Dart package, without Flutter or Keybay dependencies.
- [x] Enrollment/evaluation API, typed errors, prompt-free readiness, cancellation
  and scoped secret-buffer ownership.
- [x] Bounded independent Dart ceremony verification, fresh challenges, required
  user verification, repeatability checks and persisted authenticator state.
- [x] Swift Apple, Kotlin/JNI Android and C++ Windows OS-provider adapters.
- [x] Apple/Android host smoke tests, Windows cross-compilation, Dart tests and
  Linux container checks. These are not complete platform qualification.
- [x] Provisioned macOS native demo and consumer-owned AASA test fixture.
- [x] macOS native-demo enrollment and matching PRFs; its retained marker was
  subsequently decrypted by the normal Keypass() in-process FFI release host
  with diagnostics disabled. The original worker-host timeout remains unexplained.
- [x] Browser Google Password Manager enrollment and separate-process decryption,
  retained as scoped historical evidence.

The public API, binding encoding and packaging contract remain experimental.

## 1. Finish OS-provider qualification

Sequencing update — 2026-09-30: the core macOS enrollment/restart flow is
verified. Continue hardware and consumer implementation now; Android provider
verification is deferred at the user's request. Remaining device checks are
release qualification gates, not prerequisites for all further implementation.
The user approved Flutter solely as the iOS/Android/macOS test-app embedder.
Keypass remains a standalone Dart package; its passkey path uses native FFI,
without Flutter passkey plugins or method channels.

- [x] Recover the retained macOS credential/marker in a fresh packaged native
  FFI process (PID 44622), with the public constructor and diagnostics disabled.
- [x] Restart the normal macOS FFI host and decrypt its persisted marker
  (PID 44622 to PID 89935), with diagnostic decoration disabled.
- [x] Cancel a macOS system passkey request and verify the next explicit
  unlock decrypts the retained marker through the normal FFI client.
- [x] Complete new enrollment and restart recovery through the normal macOS
  FFI constructor (PID 89935 to PID 64043); the original credential and
  recovered fixture remain preserved.
- [x] Prove enrollment and fresh-process authenticated decryption in a packaged
  in-process Dart/FFI consumer: physical iPhone 16 / iOS 18.7.3, signed release
  diagnostic host. Enrollment PID 9337; restart recovery PID 9385. The diagnostic
  wrapper uses the normal native backend; validation.md records the exact scope.
- [ ] Finish broader in-process consumer failure/lifecycle qualification and
  verify the undecorated production constructor path on iOS. The normal Mac
  constructor passed the core flow; the iOS diagnostic writes alter timing,
  so the earlier iPhone repeated-prompt report is not considered explained.
- [x] Implement one interactive provider test app for iOS, Android and macOS,
  with a Flutter test host and the public Keypass API over native FFI. Builds
  and device qualification are recorded separately in validation.md. Release
  builds now run on macOS, a physical iPhone and the Android emulator; provider
  enrollment/restart evidence is scoped to each provider/device below.
- [x] Provision the iOS app and prove enrollment/restart decryption on a physical
  iPhone. The shared Apple adapter targets iOS 18+ and macOS 15+; the tested
  release used iOS 18.7.3. The provider selection remains user-controlled and
  the public receipt does not identify it.
- [x] Verify iOS provider cancellation during an existing-marker unlock, followed
  by successful authenticated decryption on explicit retry in PID 9385.
- [ ] Complete iOS background/lifecycle and provider-specific qualification;
  retain the successful encrypted marker for those checks.
- [ ] Publish the Android demo's Digital Asset Links for deliberate debug/release
  signing identities; prove Google Password Manager and each additional provider
  claimed. Test Activity rotation/backgrounding and release shrinking.
- [ ] Execute the existing Windows adapter on Windows with a real owner window,
  provider and packaged Dart consumer. Its DLL has only cross-compiled.

Acceptance: enrollment, new-process evaluation and authenticated decryption;
wrong context, missing verification, missing PRF, cancellation and late callbacks
fail without releasing a secret. A provider's availability is not proof of PRF.

## 2. Add the hardware route

### Shared API and credential contract

- [x] Represent OS-provider and physical-key enrollment explicitly while keeping
  one scoped-secret API. Existing bindings determine allowed unlock routes;
  authentication failure never silently switches credential or route.
- [x] Define and persist a stable RP namespace, credential identity, PRF input
  format/version, verification requirements and suitable transport hints.
  USB versus NFC must not produce a different credential identity.
- [x] Normalize WebAuthn PRF inputs exactly once in direct CTAP adapters.
  Keep user verification consistent: verified and unverified hmac-secret
  operations can produce different outputs.
- [x] Add an appropriate direct-hardware evidence policy to the verifier.
  Reuse cryptographic validation without inventing a browser origin or treating
  a locally supplied RP identifier as authenticated app identity. Review native
  CTAP attestation formats against the current none-attestation-only profile.
- [x] Detect hmac-secret support, enable it at enrollment, require PIN or on-key
  biometric verification and validate real output before saving enrollment.
- [ ] Handle multiple keys, PIN retries/blocking, removal, NFC connection loss,
  full credential storage, cancellation and unsupported keys without fallback.
  Never reset a key or erase unrelated credentials during setup or recovery.
  USB has explicit selection and typed PIN/device/storage errors. The iPhone
  NFC adapter closes its session on cancellation/backgrounding and separates PIN
  entry from scanning. Neither retries PINs automatically; physical failure and
  connection-loss qualification remain open.

Provider v2 bytes remain unchanged. Hardware v3 binds its explicit route,
required UV policy and transport hints. The current hardware adapters accept one
binding per ceremony; transport hints do not prove physical interoperability.

### Platform adapters

- [x] Implement macOS/Linux libfido2 C ABI and Dart FFI, USB discovery,
  application PIN/touch/key-selection callbacks, explicit required verification,
  bounded cancellation, and a standalone Dart encrypted-marker CLI.
- [x] Verify macOS USB hardware enrollment, matching PRFs, and authenticated
  decryption in a fresh standalone Dart process with the connected YubiKey
  firmware 5.4.3 (enrollment PID 72091; recovery PID 73444).
- [ ] Qualify that USB adapter with physical keys on both hosts, including
  unplug/reconnect, cancellation/retry and wrong-key paths. Native dependency
  packaging and Linux device-permission qualification remain outstanding.
- [ ] Windows: qualify an OS-mediated physical-key path with normal user
  privileges, proper prompt ownership and PRF results. Direct HID access is not
  a reason to require administrator privileges for routine unlock.
- [x] Android: Kotlin/JNI hardware module for USB and NFC using YubiKit FIDO
  2.9.0's protocol layer with generic Android USB HID/IsoDep connections. No
  vendor discovery or optional UI module; the consumer supplies PIN/selection UI.
  Native four-ABI builds, protocol and binary-broker tests passed.
- [x] Decrypt the retained Mac-created marker over Android NFC with the same
  physical key in the ordinary Keypass.hardware debug/JIT consumer: Pixel 6a,
  Android 16, PID 25671; two scans, one PIN prompt, authenticated decryption.
- [ ] Complete Android fresh-process repetition, USB, cancellation, removal,
  NFC enrollment and production AOT packaging qualification.
  Android OS-provider qualification remains a separate deferred task.
- [x] iOS: implement direct NFC CTAP using released YubiKit Swift 1.4.0, a
  standard FIDO AID and capability checks without manufacturer allowlists. Link
  it through hardware binary FFI with PIN/cancellation/lifecycle handling and an
  isolated signed demo screen. Memory limits and the packed-ES256 attestation
  profile are documented in [the adapter](../native/hardware_apple/README.md).
- [x] Decrypt the Mac-created hardware marker on the iPhone over NFC with the
  same physical key and ordinary Keypass.hardware client (2026-10-01, PID 31460;
  two scans, one PIN prompt, authenticated decryption success).
- [ ] Repeat iPhone fresh-process recovery and cancellation/connection loss;
  qualify NFC enrollment separately. Wired iPhone USB remains unimplemented.
- [ ] Qualify desktop NFC readers separately; do not infer desktop support from
  a successful phone NFC test.

Dependencies to evaluate: [libfido2](https://developers.yubico.com/libfido2/),
[Android YubiKit](https://developers.yubico.com/yubikit-android/fido-android-ui/index.html),
and [YubiKit Swift](https://github.com/Yubico/yubikit-swift).
Review supported releases, licensing, native packaging and secret handling before
pinning dependencies. SDK support is implementation evidence, not a Keypass test.

Acceptance: create one hardware credential on a desktop, decrypt after a fresh
process and USB removal/reinsertion, then decrypt with that same credential over
phone NFC and on each supported host. Repeat using fresh transport sessions.
Wrong key, missing verification, malformed evidence and unsupported PRF must fail.
No browser, Keypass endpoint or physical-key secret stored as a software fallback.

## 3. Consumer packaging and API completion

- [ ] Package native dependencies for Dart JIT and distributed AOT consumers.
  App signing, Gradle dependencies and UI lifecycle remain packager concerns.
- [x] Configure one explicit RP ID on the client, without runtime pubspec reads
  or a per-operation host handle. Direct hardware requires no live website.
  Native app associations remain consumer host configuration.
- [x] Integrate hardware prompts and cancellation with interactive CLI consumers;
  avoid PINs/secrets in argv, environment variables, logs or persistent state.
- [x] Version the binding format deliberately and preserve existing development
  credentials, or provide explicit migration errors. Do not silently re-enroll.
- [ ] Document provider versus hardware setup and truthful capability errors.
  Do not promise every key, phone connector, NFC reader or OS version.

## 4. Keybay integration

- [ ] Implement passkey requests through the existing credential/open/auth APIs;
  callers should not need to construct a Keypass client themselves.
- [ ] Review and implement the authenticated multi-method envelope format.
  Provider passkeys, physical keys and passphrases are separate enrolled routes
  unless an explicit policy requires multiple factors.
- [ ] Preserve mandatory platform protection and passphrase behavior. Keypass
  hardware support on Windows does not add a Windows platform root to Keybay.
- [ ] Implement atomic add/replace/remove, interruption/concurrent-writer safety,
  rotation, migration and old-client rejection. Enrollment failure preserves the
  previous usable methods; revocation cannot invalidate already copied snapshots.
- [ ] Prove recovery with a second hardware key or a separately enrolled
  passphrase, and loss/deletion/reset of one credential.
- [ ] Keep record get/set/list and authentication listing prompt-free.

[Keybay integration](keybay-integration.md) owns the detailed consumer boundary.
A portable hardware credential does not itself make a host-bound Keybay vault
portable or bypass its required platform root.

## 5. Release qualification

- [ ] Physical-device matrix covering provider, hardware model/firmware,
  OS version, app packaging and transport. Record evidence per supported cell.
- [ ] Fresh-process and fresh-device-session equality; USB-to-NFC interoperability;
  provider sync where claimed; offline behavior tested separately per route.
- [ ] Cancellation during each stage, host lifecycle loss, PIN lockout, multiple
  attached keys, interrupted writes and cleanup of late native results.
- [ ] Independent review of derivation, evidence validation, identity boundaries,
  memory limits and Keybay envelopes. Freeze formats after those findings.
- [ ] Run real CI/release packaging on supported targets; current local build
  receipts do not prove remotely executed CI or end-user installation.

## Execution order

The macOS provider restart proof is complete. The shared hardware API, v3
binding/evidence contract, macOS/Linux libfido2 USB adapter, and standalone Dart
CLI are implemented. The physical YubiKey passed macOS enrollment and
fresh-process authenticated decryption. The iPhone NFC adapter is implemented and
built in the signed demo, and the retained Mac ciphertext decrypted successfully
on the iPhone with the same key over NFC. Restart and failure-path checks remain.
Android USB/NFC implementation and native tests are complete; the Pixel 6a
debug consumer decrypted the retained Mac marker over NFC with the same key.
Android restart, USB and failure-path checks remain. At the user's request, further iPhone
checks are deferred. Finish physical failure checks and Linux/Windows/Android
qualification before claiming cross-platform physical-key support.
Build/test receipts and live outcomes are recorded in validation.md.

Android provider verification is deferred while implementation proceeds. The
same hardware credential has now recovered the marker over both phone NFC paths;
broaden lifecycle/packaging qualification before freezing the binding/API contract.
Complete native packaging and integrate
Keybay after the shared contract and both routes have repeatable-secret evidence.
Remaining provider/device checks, recovery testing and security review still
precede supported-platform and release claims.

User interaction is required for PIN/biometric/touch approval and real phone/key
tests. Do not inspect or automate provider UI while the user handles a prompt.
No device ceremony should be started merely to inspect progress.

The [research snapshots](research/2026-09-29-cli-passkey-access.md) preserve prior
alternatives. This plan is the authority for accepted scope and remaining work.
