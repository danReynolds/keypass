# Bootstrap validation — 2026-09-28

Local host: macOS 26.2 (25C56), arm64. Dart 3.12.2. Apple Swift 6.3.3.

- `dart analyze --fatal-infos`: no issues.
- `dart test`: 42 tests passed using a synthetic backend.
- `dart format --output=none --set-exit-if-changed lib test example`: clean.
- `dart run example/keypass_example.dart`: prints `backendUnavailable`, as intended.
- `dart compile exe example/keypass_example.dart -o build/keypass-example` and
  executing the binary: succeeds on macOS arm64 and prints `backendUnavailable`.
- `xcrun swiftc -typecheck native/apple/PlatformPrfProbe.swift`: succeeds with the
  installed macOS SDK. A local module-cache directory was used for sandboxing.

These results qualify the Dart foundation and an Apple API compilation probe.
No native adapter, WebAuthn signature verifier, signed host, real credential,
biometric prompt, provider sync, offline access or Keybay integration was tested.
The GitHub Actions matrix is configured but has not run. Linux, Windows, Android,
iOS and the minimum Dart SDK have not been executed locally.

## Browser proof added — 2026-09-28

Same local Mac. Node v22.23.0. The probe is outside lib/ and does not enable the
public Keypass backend.

- Dart analysis with fatal infos: clean.
- Complete Dart suite: 50 passing tests (42 original + 8 browser/marker tests).
- Node browser-module suite: 12 passing tests using generated ES256 signatures
  and synthetic PRF output.
- Dart format check across lib/test/example/tool: clean.
- Node WebCrypto and Dart cryptography complete a paired, encrypted loopback
  request/result exchange. Negative tests cover incorrect Origin, duplicate peer,
  pairing rejection, ciphertext tampering, replay/reflection, cancellation,
  timeout and mismatched encrypted restart markers.
- An actual Codex in-app browser loaded the localhost helper, showed the same
  complete comparison code as the unsigned Dart JIT CLI, and decrypted the
  request after both confirmations. It reached the create-test-passkey button.
  No credential was created and no provider PRF output was obtained.
- A second actual browser run confirmed that Cancel sends an authenticated abort
  and the CLI exits, including while terminal pairing approval is pending.
- The standalone probe compiled to an unsigned macOS AOT executable and ran its
  help command. The browser handshake itself was exercised with JIT, not AOT.
- Chrome was unavailable through the enabled automation surface. In-app-browser
  evidence does not qualify Chrome, Safari or Firefox.

Still unverified: real passkey creation/evaluation/restart, production HTTPS to
loopback restrictions/permissions, Linux and other OS execution, provider sync,
offline access, the final pairing UX and independent security review. The SDK
still returns backendUnavailable. No Keybay production code was changed.

## Provider-test preparation and cancellation fix — 2026-09-28

- Normal Google Chrome 153.0.8010.53 was reached through native macOS UI control.
  The Chrome extension automation surface is unavailable, but Chrome itself is
  installed and usable. Localhost pairing and encrypted request delivery worked;
  the browser reached Create test passkey. Credential creation was handed to
  the user and is pending, so this is not a real-provider PRF success receipt.
- The helper now exposes finite redacted failure categories and operation stage,
  without forwarding arbitrary provider messages. NotAllowedError remains
  ambiguous rather than being classified as definite cancellation.
- Fixed a real cancellation ownership gap: a provider resolving after its
  enclosing gesture promise had been cancelled could leave the returned secret
  unconsumed. The gesture wrapper now clears late Uint8Array results and invokes
  provider methods directly in the click handler to preserve user activation.
- Added tests for that late-result path, waiting/pre-cancelled gestures, exactly
  one provider invocation, provider-error propagation, error-message redaction,
  and saved-binding reuse without replacement enrollment.
- The complete Node browser-module suite passes 21 tests. The prior 50-test Dart
  receipt remains applicable; no Dart production/library code changed here.

The live Chrome tab was prepared before the gesture fix was written. A subsequent
run must load the updated helper before claiming browser qualification of that
fix. Provider approval, repeatable real PRF and restart equality remain pending.

## Live-test retry and session expiry — 2026-09-28

- The previous CLI session ended with no saved provider binding. Chrome still
  showed an enabled Create test passkey button; this was stale UI, not evidence
  that a credential was created or PRF worked.
- Fixed that bug by carrying the CLI deadline in its encrypted request. The
  helper now disables idle credential actions and cancels outstanding provider
  work when the deadline expires. The CLI independently retains its timer.
- Regression tests cover expired/invalid deadlines, an idle creation button,
  late secret cleanup after expiry, and authenticated deadline transport.
- Dart analysis is clean; all 50 Dart tests and 24 browser-module tests pass.
- A fresh CLI was started, but native UI control reported that the Mac was
  locked and automatic unlock failed. No credential-creation action was taken.
  The temporary CLI and helper server were stopped to avoid another stale run.
- Real-provider creation, repeated PRF, and restart proof still require an
  unlocked Mac and user-controlled credential/biometric approval. No vault opened.

## First real provider receipt — 2026-09-28

- macOS 26.2 arm64, normal Chrome 153.0.8010.53, Google Password Manager,
  localhost RP and static localhost helper. The updated helper was reloaded.
- The user created the development passkey. Chrome reported it saved in Google
  Password Manager; two subsequent assertions displayed Touch ID prompts.
- The browser verified both assertion signatures and equal 32-byte PRF outputs.
  The Dart JIT CLI received the result over the paired encrypted channel and
  exited successfully. The complete pairing code was compared before approval.
- The CLI saved only public binding metadata and an AES-GCM encrypted restart
  marker. Metadata-only inspection confirmed the expected file structure; the
  PRF value was neither printed nor persisted.
- The current probe also compiled to macOS arm64 AOT. `codesign -dvv` reports
  linker ad-hoc signing with no TeamIdentifier or bound Info.plist; no Apple
  developer signing or associated-domain entitlement was configured.

This establishes real provider creation and within-run repeatability for this
specific browser/provider/host. The separate AOT restart-marker check is pending.
It does not qualify HTTPS-to-loopback, Linux, Apple Passwords, Safari, native
adapters, synchronization, offline use, the public SDK backend or Keybay vaults.

### AOT restart attempt result

The separate AOT process exited with failure. Chrome showed `notAllowed` during
Verify passkey 1 of 2; this browser result does not distinguish cancellation,
timeout or a disallowed request. The saved marker was not verified, so restart
qualification remains open. The saved binding and provider credential remain
available for retry; no replacement credential is needed. The temporary helper
server was stopped after inspecting this result.

## Independent Dart verification and Linux runtime — 2026-09-28

The live retry was stopped before pairing because UI control reported the Mac
locked. No new credential was created. Both temporary servers were stopped.
The earlier real-provider receipt predates the Dart evidence-verification path;
the existing saved credential is preserved for its next restart attempt.

Implemented a bounded ES256/P-256, `none`-attestation Dart verifier and required
its checks in the CLI before saving metadata or verifying the encrypted marker.
Raw public registration/assertion data travels in the encrypted response; PRF
bytes remain a separate binary prefix, never JSON/base64 log output. The original
SPKI probe binding remains readable. See [verifier limits](webauthn-verifier.md).

- macOS 26.2 arm64, Dart 3.12.2, Node 22.23.0: analyzer clean; 85 Dart tests and
  25 browser-module tests pass. Updated AOT probe compiles and runs `--help`.
- Linux ARM64 in Docker Desktop, Dart 3.12.2 and Node 22.23.3: locked dependency
  resolution, analyzer, the same 85 Dart / 25 Node tests and AOT compilation pass.
  The compiled Linux executable runs `--help` with container networking disabled.
- Linux used an isolated source snapshot without `.git`, build output, local
  credentials or the provider binding. Official image digests were
  `dart:3.12.2-sdk@sha256:5ac89dbcae4327278b257920e2786df0f22c87adc630017266b67cfcceef8348`
  and `node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c`.
  The reusable recipe is `tool/validation/Dockerfile` with `.dockerignore`.
- New tests use independently generated Node/OpenSSL signatures and synthetic
  PRF, including altered evidence after JavaScript verification. They cover raw
  enrollment and reuse, duplicate keys, bounds, truncated registration, invalid
  flags/contexts/keys/signatures, strict DER and backup/counter policy.

Still pending: real-provider restart-marker success with the updated verifier,
a deployed HTTPS helper, actual Linux browser/provider UI, other native hosts,
sync/offline behavior, reviewed credential-state persistence and public backend
wiring, independent security review, and Keybay integration. No vault opened.

## Saved-passkey AOT restart succeeded — 2026-09-29

- macOS 26.2 (25C56), normal Chrome, Google Password Manager, localhost RP and
  localhost static helper. The installed Chrome bundle reported 154.0.8037.58
  after completion; the running browser version was not separately re-queried.
- A fresh `build/keypass-browser-probe` process reused the existing public binding
  and encrypted marker from the earlier JIT enrollment. No replacement passkey
  was created. All eight pairing-code groups matched before approval.
- The user completed both provider verifications. Browser automation/inspection
  was released for the biometric steps after the user reported interference.
- The AOT CLI exited with code 0 and reported:

  ```text
  Saved encryption check passed: the PRF matches the earlier process.
  Received 32 PRF bytes over the paired encrypted channel.
  Dart independently verified both assertion signatures and ceremony context.
  The browser checked equal PRF output across both evaluations.
  ```

This confirms recovery of the same real-provider PRF after a CLI process restart:
that output decrypted the earlier process's AES-GCM test marker. It also qualifies
both assertion checks in the new Dart verification path for this specific run.
The PRF was neither printed nor persisted, and the CLI clears its owned result
buffer on exit. The temporary helper server was stopped after collecting the
result. No operating-system reboot or browser restart was required or claimed.

The saved legacy SPKI binding has no raw registration attestation or persisted
backup/counter state. This run therefore does not qualify Dart registration
verification or counter continuity across processes. Deployed HTTPS-to-loopback,
Linux desktop/provider behavior, other providers, native adapters, synchronization,
offline use, public SDK wiring, independent review and Keybay vault integration
remain pending. No Keybay vault was opened.

## Native platform adapters — 2026-09-29

Implemented a shared Dart native backend and versioned start/poll/cancel/free C
ABI. Public ceremony evidence is bounded JSON; the PRF is a separate mutable
binary buffer. Dart verifies raw registration and assertion evidence before
returning bytes. Experimental binding encoding v2 persists backup eligibility,
backup state and signature counters; enrollment chains state through both
assertions, and unlock exposes the updated binding for consumer persistence.
Android's expected origin comes from the installed APK signing certificate,
independently of provider output. Native provider UI never falls back to another
route after an authentication failure.

| Target | Executed proof | Still unproved |
| --- | --- | --- |
| macOS 26.2 arm64 | Swift dynamic library and Swift package build; real Dart FFI rejects an unsigned CLI; native app smoke passes window discovery, malformed input, busy state and cancellation | Signed domain-associated host, real PRF, packaged Dart app, native process restart |
| iOS simulator 26.5, iPhone 17 Pro | Adapter and isolated UIKit host compiled, installed and launched; native app smoke passes presentation and ABI/cancellation checks | Actual passkey/provider PRF, app association, real device, Dart embedding and lifecycle |
| iOS device SDK | Adapter typechecked for arm64/iOS 18 deployment target | Physical-device execution, signing and real-provider behavior |
| Android API 33 AOSP emulator | Kotlin/JNI adapter built for four ABIs; isolated app passes Activity discovery, APK signing-origin derivation, JNI delivery and cancellation; debug/release packaging succeeds | Google/third-party provider PRF, Digital Asset Links, rotation during prompts, real devices and release shrinking |
| Windows x64 | DLL cross-compiled with MinGW against pinned official Microsoft header; warnings treated as errors, SDK header treated as a system include | Windows execution, MSVC CI run, app HWND, each provider, deployment/runtime dependencies |
| Linux ARM64 container | Strict analyzer, 97 Dart tests (Apple-only test skipped), 25 Node tests, browser-probe AOT compilation | Linux desktop browser/provider, deployed HTTPS helper, public browser backend |

macOS strict analyzer and all 98 Dart tests passed, including independent signed
native evidence, persisted counter replay rejection, Android origin policy,
per-credential PRF mapping, native buffer cleanup on malformed data, and late
success after cancellation. All 25 Node browser tests also passed. The AOT
example compiled and correctly reported `backendUnavailable` without a linked
native host. Synthetic PRF fixtures are not real-provider evidence.

Local artifacts: `build/native/libkeypass.dylib`, the Swift package's `.build`
product, `native/android/build/outputs/aar/keypass-native-release.aar`, and
`build/native/keypass.dll`. Smoke receipts are in `build/native/`; repeatable
source/scripts live in `native/*` and `tool/apple_native_smoke.sh` /
`tool/windows_cross_check.sh`. Docker images are
`keypass-validation:20260929-native` and `keypass-windows-cross:20260929`.
The Linux validation image needed a C compiler for the new FFI fixture; that
build dependency is now explicitly installed by its recipe.

The macOS smoke exposed a host-selection gap: a sole visible eligible app window
can exist without a current key/main window. The resolver now handles that
unambiguous case. The Android smoke led to guarding cancelled queued requests
before dispatching provider work. Test simulators started for this run were shut
down after their receipts were collected.

No native test created a passkey or decrypted a vault. The earlier browser
restart success is still the only real-provider PRF/restart proof. Native
qualification awaits the user's HTTPS RP domain, public Apple/Android app
association, a matching Apple Associated Domains provisioning profile, and
device/provider runs. Apple signing identities are available locally. Keybay's vault
format and consumer integration are still the later milestone. Automatic
pubspec embedding and public browser-backend wiring remain unfinished. CI jobs
were added for native builds but were not pushed or executed remotely.


## Interactive macOS demo — 2026-09-29

Built, signed with an ad-hoc development signature, launched and visually checked
`build/demo/Keypass Demo.app`. Its connection check passed through the AppKit
host, private binary pipe transport and bundled AOT Dart SDK worker. The strict
analyzer and five focused demo tests passed: fragmented framing, input cleanup,
malformed/truncated frames, encrypted marker continuity, authenticated binding
updates and rejection of a different PRF key.

The app remains unconfigured while the RP domain and matching Associated Domains
profile are selected. Create/unlock are disabled; no native provider or biometric
prompt was invoked. This proves the packaged demo bridge, not provider PRF or
in-process Dart FFI integration. The earlier browser run remains the real-provider
restart proof. See [the demo guide](demo.md) for launch/signing instructions and
current demo coverage on each platform.


## Provisioned macOS demo and HTTPS association — 2026-09-29

Created the dedicated Firebase project/site `keypass-demo-20260929` and deployed
only `demo/hosting/public/.well-known/apple-app-site-association`. Cloud Billing
reports `billingEnabled: false`. The HTTPS endpoint and Apple's association CDN
both returned HTTP 200, `application/json`, no redirect, and the expected
`webcredentials.apps` entry `5AHFA9FUZG.dev.keypass.demo`.

Xcode automatic signing registered/provisioned the separate `dev.keypass.demo`
app under team `5AHFA9FUZG`. The embedded Mac Team Provisioning Profile authorizes
Associated Domains and expires 2027-09-29. The built app's signed entitlement is
`webcredentials:keypass-demo-20260929.web.app`. Recursive strict code-signature
verification passed for the app and bundled worker.

`sh tool/build_provisioned_macos_demo.sh` built the configured app at
`build/demo-signed/Keypass Demo.app`. Launched it with `--check`; the public
receipt reported `configured: true`, `busy: false`, `saved: false`, and
“Native host and Dart SDK connected. Ready to attempt a passkey ceremony.”
The earlier unconfigured demo process was stopped. No provider UI was driven
while the user was invited to create a test passkey.

This completes hosting and Apple app-association/signing setup. A successful
native enrollment and restart decryption still need user interaction. iOS uses
the same published app identity only if its own signed host is provisioned with
that bundle ID; no iOS profile or Android association was created in this run.

## Native macOS enrollment receipt observed — 2026-09-29

A read-only inspection of build/demo-signed/macOS-receipt.json found
configured=true, busy=false, saved=true and this completion message:

> Passkey created. Both PRFs matched; the encrypted test marker is saved. Quit and reopen to check recovery.

The demo source emits this status only after Keypass.enroll returns and the
encrypted marker is saved. Enrollment runs the Dart registration/assertion
verifier and compares two PRF evaluations. This is evidence for successful
native AuthenticationServices enrollment and within-process repeatability in
the provisioned macOS demo, beyond the earlier connection-only receipt.

This audit did not trigger another ceremony, inspect biometric UI, read the
saved credential/marker payload, or rerun tests. The receipt does not identify
the selected provider or biometric method. It does not prove native restart
decryption, provider sync, offline access, mobile hardware behavior or in-process
Dart embedding. The demo still uses its bundled AOT worker/private pipe.
The browser run remains the recorded separate-process decryption proof.

The updated [implementation plan](implementation-plan.md) records OS-provider
and physical-key routes as accepted scope. No physical-key adapter or Keybay
passkey integration was added by this documentation update.

## In-process provider test hosts — 2026-09-29

The user approved Flutter for the disposable test apps only. The root SDK
still has no Flutter dependency. [The provider app](../demo/provider_app/README.md)
calls the public Keypass constructor and native FFI transport, linking the same
Swift source and Android library module used by the standalone adapters.

Completed in this run:

- Root analyzer: no issues. All 110 Dart tests passed, including seven new
  shared-store tests. After moving the shared store into the demo app, all 12
  demo tests passed. The wrong-PRF and metadata-tampering tests were then
  tightened to require SecretBoxAuthenticationError; all seven store tests
  passed again. These use synthetic providers, not device credentials.
- Flutter demo analyzer: no issues.
- macOS and iOS release builds succeeded through Xcode automatic provisioning;
  both signed bundles passed codesign --verify --deep --strict.
- The macOS executable exports all five Keypass C ABI symbols. Its release-mode
  receipt at PID 82035 reports in-process FFI readiness, busy=false, saved=false.
  No credential was requested by this automatic connection check.
- The signed iOS app dev.keypass.providerDemo was installed and launched on a
  physical iPhone 16 running iOS 18.7.3. Its release-mode receipt at PID 4649
  records an enrollment attempt ending prfUnavailable, busy=false, saved=false.
  Provider selection and the precise failure stage are not established by this
  receipt. It is a failed PRF-enrollment result, not successful encryption proof.
- The isolated demo site now serves both AASA and Android Digital Asset Links.
  The new Apple app ID is authorized alongside the original app; direct HTTPS
  responses and Apple's updated CDN copy were verified. The Android association
  deliberately lists only this machine's demo development-certificate fingerprint.

The original AppKit/worker demo was reopened in a new process (PID 43732), while
preserving its earlier marker. Its observed receipt still reports connection
readiness, not restart decryption. The user-controlled unlock result is pending.
Neither credential payloads nor raw PRF bytes were read or printed.

Real provider enrollment/restart for the new in-process apps, cancellation and
lifecycle qualification, Android phone testing and Windows runtime qualification
remain outstanding. The Android AOSP emulator has no Google passkey provider.
The selected provider's PRF support must be tested separately from OS/API
availability. Hardware and Keybay integration were not started in this stage.

### Android release consumer and standalone Dart checks

The shared Android app's release APK built successfully (50.5 MB), with the
native adapter included. apksigner verification succeeded and its SHA-256
signing certificate matched the published demo assetlinks.json. It was installed
and launched on the existing Android 33 AOSP arm64 emulator. The app receipt
records release=true, transport=in-process FFI, operation=check, code=null and
the native FFI readiness message at PID 2307. This exercises the packaged
release Dart code, JNI bootstrap, Activity selection and C ABI after shrinking.
It does not establish provider PRF support; no credential was requested.

The Android build uses the adapter's current Gradle 8.10.2 / AGP 8.8 / Kotlin 2.1
baseline. Flutter 3.44.4 warns that these versions will be unsupported by future
Flutter releases; modernization remains a packaging task, not a passed future
compatibility claim.

After the shared-source imports were finalized, root dart analyze --fatal-infos
passed again and tool/demo/worker.dart compiled to a standalone AOT executable
without Flutter. The root validation commands now format the shared pure-Dart
store explicitly and exclude nested Flutter caches from Docker context.
Seven updated documentation files passed local-link validation.

Apple's documented registration-support check and isSupported output match the
adapter's current request/response mapping:
[registration input](https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentialprfregistrationinput-c.class)
and [registration output](https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentialprfregistrationoutput-swift.struct).
That code review does not identify the provider or explain the observed iPhone
failure; no compatibility workaround or weakened PRF check was introduced.

Android force-stop/relaunch returned LaunchState=COLD and a new process
(PID 2383). Its release FFI readiness check passed again. This is initialization
after restart, not encryption recovery. The headless emulator was started for
these checks and stopped afterward.

The original Mac demo's Unlock saved test button was invoked once after observing
its idle state. UI automation stopped immediately before provider interaction.
Its public receipt then reported busy=true and the expected approval request;
the user-controlled result remains pending.

### iPhone reconnection — 2026-09-29 local time

The paired iPhone became available again. The earlier demo's app-data container
could not be resolved and the device app inventory contained no Keypass app.
The existing signed release build was reinstalled and launched successfully.
Its public receipt reports PID 8792, started 2026-09-30T01:35:09.311962Z,
release=true, transport=in-process FFI, operation=check, code=null, busy=false,
and saved=false. Native FFI readiness passed on the physical phone.

At this checkpoint enrollment had not started. The user was asked to select
Apple Passwords/iCloud Keychain if offered, to narrow the previous unattributed
prfUnavailable result. No provider was inferred, no credential payload was read,
and no biometric/provider UI was inspected or controlled. Enrollment followed
by fresh-process authenticated decryption remains pending.

### LastPass-selected iPhone attempt — 2026-09-29 local time

The user confirmed that enrollment opened LastPass and that the new passkey
appears in LastPass's passkey list. Their supplied screenshot shows the demo
ending with prfUnavailable, Unlock saved test disabled, and no encrypted test
saved. This attributes this attempt to the LastPass iOS provider route: provider
credential creation succeeded, but Keypass did not obtain the PRF material
required to enroll an encryption method. The LastPass app version and precise
failed stage were not captured. This is not a product-wide claim about all
LastPass versions or platforms, and does not retroactively identify the provider
used in the earlier attempt.

No LastPass vault contents were inspected by automation. The evidence is the
user's report plus the supplied demo screenshot. A provider credential can
remain saved even when the later PRF capability or repeatability check rejects
Keypass enrollment. The next comparison is an explicitly selected Apple
Passwords/iCloud Keychain credential on the same native app/phone.


### Apple Passwords host lifecycle failure — 2026-09-29 local time

The user explicitly selected Apple Passwords for the next iPhone attempt and
reported `hostUnavailable`. The public receipt from PID 8792 confirms
operation=enroll, code=hostUnavailable, busy=false and saved=false. This is a
presentation-host failure, not a PRF-capability verdict. The receipt does not
identify which native operation failed.

Code review found that each native request immediately required an active
foreground scene. Enrollment performs registration followed by two assertions;
a callback arriving before the provider sheet finishes dismissing could make
the next request fail during the scene's inactive transition. This timing
explanation remains a hypothesis pending the phone retry.

The adapter now waits, using lifecycle notifications with a three-second
deadline, for the same foreground window to become active and key. It refuses
missing/ambiguous hosts, window changes and background/disconnected scenes.
Cancellation removes the waiter and prevents a late prompt. Seven Swift
regression tests passed, covering immediate readiness, consecutive ceremonies,
window changes, unavailable hosts, background/disconnection, cancellation and
timeout. The updated source typechecked against both iPhone and iOS simulator
SDKs. These tests exercise the presentation gate, not actual provider callbacks.

The demo now explains PRF and window failures in plain language while preserving
typed error codes in its public receipt. A failed enrollment may still leave
a credential in the selected provider, without an encrypted test on disk.
Rebuilt-app installation and device enrollment/restart recovery remain pending
at this checkpoint.

Apple documents the distinction between foreground-active and foreground-inactive
scenes in [scene activation state](https://developer.apple.com/documentation/uikit/uiscene/activationstate-swift.enum).
This supports the lifecycle handling, but does not prove the timing of the
observed failed ceremony.


The updated demo passed Flutter analysis and its signed iPhone release build
succeeded. Signature verification passed with access to the host trust service
(the sandbox-only attempt could not access certificate trust). The update was
installed and launched on the same iPhone. Its new public receipt reports
PID 9179, started 2026-09-30T02:01:13.112512Z, release=true, in-process FFI,
operation=check, code=null, busy=false and saved=false. This confirms startup
of the rebuilt app; it does not yet confirm a successful Apple Passwords
ceremony. Manual enrollment and fresh-process marker decryption are pending.

### Repeated Face ID prompt report — 2026-09-29 local time

On the rebuilt iPhone app the user reported that "use Face ID to sign in"
kept looping. The public receipt for PID 9179 subsequently showed operation=enroll,
code=cancelled, busy=false and saved=false. It contains no per-ceremony history,
so it cannot distinguish two expected sign-in checks from repeated prompts
inside one Apple authorization request. No provider UI was inspected.

The current core issues one registration followed by exactly two assertions,
with no retry loop. The native adapter calls performRequests once per ceremony;
its presentation gate completes once. The FFI polling loop waits for the result
and does not reissue the request. This code review does not identify the cause
of the reported provider behavior.

The diagnostic demo now displays numbered enrollment steps and records only
fixed register/evaluate phase labels, timestamps and request counts in its
public receipt. It uses the backend integration surface to decorate the same
native backend as the default Keypass constructor. This is test-app wiring;
the SDK's public API, native requests and cryptographic validation are unchanged.
Progress succeeds only after the underlying backend returns, including its
verification. Diagnostic failures cannot retry or replace a provider operation.

The three diagnostic tests and 21 existing client tests passed (24 total);
demo Flutter analysis and standalone Dart analysis are run for this build.
Actual device diagnosis and successful enrollment/restart decryption remain
pending. Request-count instrumentation is not an OS-provider compatibility fix.

The diagnostic iPhone release build and signature verification passed. After
installation/relaunch, the public receipt reports PID 9337, started
2026-09-30T02:12:26.342089Z, operation=check, code=null, busy=false, saved=false,
and zero registration/evaluation requests. Both standalone Dart and Flutter
analyzers passed. No manual credential operation has been observed in this new
process yet; retry remains user-controlled.

### iPhone enrollment succeeds — 2026-09-29 local time

The user completed the diagnostic run. The public receipt from PID 9337 shows
operation=enroll, code=null, busy=false and saved=true. Exactly one registration
and two evaluations started, and all three returned successfully:

- Registration: 2026-09-30T02:13:59.543447Z to 02:14:04.084490Z.
- First assertion: 02:14:04.085770Z to 02:14:08.756490Z.
- Second assertion: 02:14:08.758210Z to 02:14:13.339906Z.

Both verified PRF results matched and the authenticated encrypted marker was
saved. There was no application request loop in this observed run. Provider
selection is user-controlled; the retry instructions specified Apple Passwords,
but the public receipt itself does not identify the selected provider.
This successful diagnostic run does not retroactively establish the cause of
the earlier repeated-prompt report. The diagnostic reporter adds receipt writes
between operations, so timing differs from the undecorated consumer path.

Fresh-process decryption is the next gate. Only the public progress receipt was
read; no credential identifiers, bindings, PRF bytes or encrypted-test payloads
were inspected.

The app was then terminated/relaunched, preserving its data. The new receipt
shows PID 9385, started 2026-09-30T02:15:16.152295Z, operation=check, code=null,
busy=false, saved=true and zero new credential requests. The marker survived
the process restart; its authenticated decryption still awaits manual unlock.

### iPhone fresh-process decryption succeeds — 2026-09-29 local time

The user completed Unlock saved test in the restarted process. Its public
receipt reports PID 9385, operation=unlock, code=null, busy=false and saved=true,
with the success status confirming authenticated decryption of the saved marker.
Exactly one evaluation ran (2026-09-30T02:18:25.033541Z to
02:18:28.590592Z), and no registration was requested.

Enrollment occurred in PID 9337 and recovery in PID 9385. Together these
receipts demonstrate repeatable passkey-derived encryption material across
process termination/restart and successful AES-GCM marker authentication and
decryption on this physical iPhone 16 / iOS 18.7.3, signed release FFI host.
The saved test remains available. No binding, credential identifier, encrypted
payload or raw PRF output was inspected.

Scope: this is the diagnostic host and user-selected provider flow described
above. It does not establish all iOS providers, sync/cross-device recovery, or
the cause of the earlier looping report. Before marking OS-provider qualification
complete, still exercise cancellation of an existing-marker unlock followed by
successful retry, host/background lifecycle cases, and the undecorated production
constructor path. Other platform gates remain independent.

### iPhone unlock cancellation — 2026-09-29 local time

The user cancelled the system prompt during an existing-marker unlock. The
public receipt from PID 9385 reports operation=unlock, code=cancelled,
busy=false and saved=true. Exactly one evaluation started at
2026-09-30T02:20:38.957569Z and failed at 02:20:43.438392Z; there was no
registration or automatic retry.

This verifies propagation of provider cancellation and that the saved test
file remains present. The receipt does not prove its contents are unchanged;
successful authenticated decryption on the next manual retry is still required
to complete the cancellation/recovery check. No credential or marker payload
was read.

### iPhone unlock retry after cancellation succeeds — 2026-09-29 local time

The user approved a subsequent unlock in the same restarted process. The public
receipt from PID 9385 reports operation=unlock, code=null, busy=false and
saved=true, with successful authenticated decryption of the saved marker.
Exactly one evaluation ran from 2026-09-30T02:25:54.833764Z to
02:25:58.284876Z, with zero registrations.

This completes the real-device existing-marker cancellation/retry check: the
provider cancellation was returned without automatic retry, and the next
explicit unlock recovered the original encryption secret and decrypted the
marker. The same demo now has observed enrollment, fresh-process recovery,
provider cancellation and successful recovery after cancellation.

Scope remains the diagnostic release FFI host on this physical iPhone and the
user-selected provider. Broader lifecycle/provider combinations, sync recovery,
and enrollment timing through the undecorated production constructor remain
open. Only the public status receipt was inspected; the encrypted test and
provider credential are retained for further qualification.

### macOS continuation and ordinary constructor build — 2026-09-30

The user moved on from iPhone testing and authorized macOS qualification.
The original saved-marker demo was no longer running. Its retained public
receipt (PID 43732) ended with timeout, busy=false and saved=true; it is historical,
not a current unlock result. Strict recursive signature verification passed.
The app was reopened as PID 22572 with AOT worker PID 22602, and the user was
asked to approve Unlock saved test. This launch omitted KEYPASS_DEMO_RECEIPT,
so that original receipt file will not update; do not infer a new result from it.
No provider UI was inspected or automated.

The separate FFI demo's previous process (PID 82035) was idle with saved=false
and was terminated before rebuilding. Its default construction now uses
Keypass() directly; the existing diagnostic decorator is opt-in via the Dart
define KEYPASS_DEMO_PROGRESS=true. Without diagnostics, no progress receipt
writes occur between native requests and provider counters are null, not zero.
The receipt explicitly names the construction mode and whether diagnostics run.

Flutter analysis passed. The signed macOS arm64 release build succeeded and
passed codesign --verify --deep --strict. All five C ABI symbols are exported.
The new FFI app has not yet been launched, to avoid disrupting the user's prompt
in the original demo. Its own enrollment/restart/cancellation checks remain
pending. The installed iPhone binary was not rebuilt or changed.

### Original Mac timeout and direct FFI recovery attempt — 2026-09-30

After the user reported completing the original demo prompt, the app's visible
status read "Operation stopped: timeout." Cancel was disabled and Unlock was
enabled. This is a failed attempt, not a successful recovery claim. The optional
original-demo receipt was not enabled for that process, so the current result
was read from its completed app UI.

The original app and worker were closed. Its disposable encrypted test was
copied as opaque bytes to the previously empty FFI demo test directory, with
exclusive creation and no overwrite. The original file was preserved; neither
payload was decoded, printed or inspected. This uses the documented shared
demo format to test the retained credential through a different packaged host.

The signed direct FFI app launched as PID 44622, started
2026-09-30T14:03:27.505907Z. Its public receipt reports release=true,
transport=in-process FFI, client=Keypass(), providerProgress=false,
operation=check, code=null, busy=false and saved=true. Native readiness passed;
provider counters are null because diagnostic decoration is disabled.
An unlock of the copied fixture is the next user-approved ceremony. Successful
decryption would qualify this recovery path but would not by itself identify
the cause of the older host's timeout or prove new enrollment in the FFI host.

### macOS normal-constructor FFI recovery succeeds — 2026-09-30

After user approval, the public receipt from PID 44622 reports operation=unlock,
code=null, busy=false, saved=true and successful authenticated decryption of
the copied original Mac marker. It explicitly identifies client=Keypass(),
providerProgress=false, release=true and transport=in-process FFI.

This proves recovery of the credential's original encryption material through
the normal packaged Dart FFI path, without the diagnostic backend decorator.
The credential and marker were created earlier in the separate AppKit/worker
host; this is fresh-process recovery and compatibility of the shared fixture
format. It is not new enrollment in the FFI host, and does not establish why
the earlier original-host attempt timed out.

The next check restarts the FFI host itself and unlocks its now-persisted marker.
The original fixture remains in the original app's directory. Only the public
status receipt was read for this result; provider UI and credential/PRF payloads
were not inspected.

The successful FFI process (PID 44622) was quit through the app controls and
its exit was verified. The relaunched app's public receipt reports PID 89935,
started 2026-09-30T18:18:36.189890Z, normal Keypass() construction,
providerProgress=false, operation=check, code=null, busy=false and saved=true.
The same-host restart unlock is now ready for user approval.

### macOS FFI host restart decryption succeeds — 2026-09-30

The public receipt from the relaunched FFI process, PID 89935, reports
operation=unlock, code=null, busy=false, saved=true and successful authenticated
decryption. The receipt continues to identify client=Keypass(),
providerProgress=false, release=true and in-process FFI. The preceding successful
process was PID 44622, whose termination was verified before this relaunch.

This establishes recovery across a restart of the ordinary packaged FFI host
itself. The underlying credential was enrolled by the earlier AppKit/worker
demo; enrollment through the normal FFI constructor remains a separate check.
The next check exercises application-requested cancellation and an explicit
retry while preserving the existing marker.

### macOS system-prompt cancellation — 2026-09-30

The agent initiated another unlock and selected Cancel in the system passkey
sheet; the user was told not to approve this cancellation check. The sheet
identified Passwords as its credential source. This observation concerns this
attempt, not retroactive attribution of earlier provider selections.

Both the app UI and public receipt from PID 89935 report cancelled,
operation=unlock, busy=false and saved=true. The normal Keypass() constructor
and disabled diagnostic wrapper are unchanged. This was system/provider UI
cancellation, rather than the demo's application-level Cancel button.
The next explicit retry must decrypt the marker before declaring cancellation
recovery complete. No provider UI will be inspected while the user approves
that retry.

### macOS cancellation retry succeeds — 2026-09-30

The public receipt from PID 89935 reports operation=unlock, code=null,
busy=false, saved=true and successful authenticated decryption after the
system-prompt cancellation. Normal Keypass() construction, release mode and
disabled diagnostic decoration are still recorded. This completes the observed
Mac existing-marker cancellation/retry check.

The current credential was originally created in the AppKit/worker demo.
To separately qualify new enrollment through the normal FFI constructor,
preserve the current FFI marker as encrypted-test.recovered-from-appkit.json
in the same private test directory, then use the empty active slot for a fresh
disposable test. The original AppKit marker and provider credential remain
available. No fixture payload needs to be decoded or displayed.

### macOS normal-FFI new enrollment succeeds — 2026-09-30

The public receipt from PID 89935 reports operation=enroll, code=null,
busy=false, saved=true and completion of enrollment with both PRFs matching.
It records client=Keypass(), providerProgress=false, release=true and
transport=in-process FFI. This is new registration and repeatability validation
through the ordinary FFI constructor, separate from recovery of the older
AppKit credential.

Before enrollment, the previously recovered fixture was retained under
encrypted-test.recovered-from-appkit.json in the same private directory. The
new encrypted-test.json is the newly enrolled marker. Neither payload nor raw
PRF material was inspected. Fresh-process decryption of this new marker is the
remaining core enrollment/recovery check for this Mac host.

The enrollment process PID 89935 was quit through app controls and its exit
verified. A new process PID 64043 started at 2026-09-30T18:47:28.398006Z.
Its public startup receipt confirms normal Keypass(), providerProgress=false,
release=true, saved=true, busy=false and code=null. The agent is initiating an
unlock of the newly enrolled marker; decryption is pending user approval.

### macOS core normal-FFI flow verified — 2026-09-30

The final public receipt from PID 64043 reports operation=unlock, code=null,
busy=false, saved=true and successful authenticated decryption of the newly
enrolled marker. It records client=Keypass(), providerProgress=false,
release=true and transport=in-process FFI. Enrollment completed in PID 89935;
that process was terminated and its exit verified before PID 64043 launched.

The core native Mac flow is now observed through the ordinary public client:
new registration, two matching verified PRFs, encryption, process termination,
fresh-process recovery and authenticated decryption. Earlier checks also proved
system-prompt cancellation followed by successful retry using the retained
original credential in the same normal FFI host. No diagnostic decorator or
inter-request receipt writes were active in these Mac checks.

The new marker, recovered original fixture backup and original AppKit marker
are retained. No provider credential was deleted, and no credential/PRF payload
was printed. The current app is idle after success; no further prompt was started.

This qualifies the tested host/credential flow, not every provider or OS version.
Sync/cross-device recovery, offline behavior and broader lifecycle/failure cases
remain release-qualification work. The original worker-host timeout was not
diagnosed by these successes. Android real-provider and Windows runtime
qualification remain separate, and hardware/Keybay integration has not begun.

## Read-only USB hardware capability probe — 2026-09-30

A physical YubiKey connected to the local Mac responded to CTAPHID INIT and
CTAP2 GetInfo using Yubico python-fido2 2.2.1 from an isolated temporary
environment. This is capability evidence, not a Keypass adapter or PRF ceremony.

- USB product: YubiKey OTP+FIDO+CCID, vendor/product 1050:0407.
- Device firmware from the HID handshake: 5.4.3; GetInfo firmware value 328707
  (0x050403) agrees.
- AAGUID: 2fc0579f-8113-47ea-b116-bb5a8db9202a, listed as YubiKey 5 Series with NFC
  in [Microsoft's authenticator catalog](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor).
  Exact USB-A versus USB-C form factor was not determined.
- Versions: U2F_V2, FIDO_2_0, FIDO_2_1_PRE.
- Extensions: hmac-secret, credProtect.
- Advertised transports: usb, nfc. Only USB communication was exercised.
- Resident credentials and user presence supported; clientPin=true indicates a
  configured FIDO2 PIN. PIN/UV protocols 1 and 2 are advertised.
- No built-in UV option is advertised. Plan PIN plus user presence, not on-key
  fingerprint verification, for this device.

No PIN was requested/submitted, credential enumerated/created/deleted, PRF
evaluated, or device setting changed. This key is a suitable candidate for the
desktop USB implementation and later same-key phone NFC tests. Real enrollment,
verified PRF repeatability, fresh-process decryption and NFC remain untested.

## Direct USB implementation and build qualification — 2026-09-30

Implemented the public `Keypass.hardware(namespace:, interaction:)` route and
a libfido2 C++/FFI USB adapter for macOS/Linux. The normal scoped-secret API
requires FIDO2 hmac-secret, resident credentials, `credProtect=3`, UP/UV and
verified assertions. Provider v2 binding serialization is preserved; hardware
v3 records its explicit route, required verification and transport hints.
Native attestation signatures are checked without claiming manufacturer trust.

Executed locally:

- macOS 26.2 arm64, Dart 3.12.2, libfido2 1.17.0, OpenSSL 3.6.3:
  native CMake build and CTest passed; Dart analysis clean; formatting clean;
  all 138 Dart tests passed, including 25 hardware tests; standalone AOT CLI
  compiled and loaded the native library beside the executable.
- The normal CLI `check` found the attached YubiKey over USB without a
  credential operation. No browser, associated-domain website or signed app
  host is involved in this hardware route.
- Linux aarch64 Docker build using the pinned Dart 3.12.2 SDK image and
  checksum-pinned libfido2 1.17.0 source passed native compilation/CTest,
  analysis, 137 Dart tests (one platform-specific test skipped), and AOT
  compilation. Native startup without a USB device returned the expected
  `deviceUnavailable`. This does not establish Linux USB-device access.
- Added macOS native and Linux container CI jobs. They have not yet executed
  on a remote CI runner.

Tests cover independently signed ES256 evidence, changed signatures, signed
wrong context/UV/UP/extensions, counter rollback/replay, required credential
protection, v3 validation, provider/hardware route isolation, mutable PIN
ownership, late-result cleanup, rejected read-only PIN buffers, missing PIN UI,
malformed interaction draining, and cancellation during key selection.

The first interactive Terminal enrollment attempt (PID 23222) reached
`waitingForPin` and then timed out with zero touch requests and no saved marker.
No PIN was submitted and no credential created by that attempt. Actual
enrollment, matching hardware PRFs, fresh-process decryption, unplug/reinsert
and physical cancellation/retry remain pending user interaction.

Remaining implementation: Windows hardware access, iOS/Android USB/NFC, desktop
NFC-reader qualification, native dependency packaging, and Keybay integration.
Advertised NFC in binding metadata is not implemented transport support.
PIN failures are not retried; tests do not reset keys, alter PINs, enumerate
credentials or erase unrelated credentials.

## Hardware Terminal retry and PIN-input regression — 2026-09-30

The authorized live retry in PID 82245 returned `backendFailure` before any
touch request and saved no marker. An isolated pseudo-terminal reproduction
with synthetic input established that the demo cancelled stdin's subscription
before restoring echo/line settings. Dart closes the native stdin descriptor
on subscription cancellation, so restoring echo then threw `StdinException`.

Fixed the demo to restore terminal settings before cancelling the subscription.
Added a POSIX pseudo-terminal driver and two permanent regression tests for
input and cancellation. These use synthetic bytes and never open a hardware
client. Both verify successful completion without echoing the synthetic input.

Rebuilt the demo. The next user-approved live attempt (PID 86256) reached the
native hardware request and returned `pinInvalid`, with one touch-status event
and no saved marker. The touch-status event is emitted before libfido2's PIN
verification and is not evidence that the physical key accepted a touch.
No automatic PIN retry, reset, PIN change or credential deletion occurred.
Further live enrollment is awaiting the user's decision about the existing
FIDO2 PIN. Encryption/restart proof remains unverified.

Validation after the fix: macOS Dart analysis clean and all 27 hardware tests
passed. Linux aarch64 container native build/CTest, analysis, all 139 applicable
Dart tests (one Apple-specific test skipped), AOT compilation and no-device
startup check passed. No human PIN, OTP or PRF output was read by the agent or
written to diagnostics.

## Second rejected FIDO2 PIN attempt — 2026-09-30

The user explicitly requested another Terminal test. PID 37758 returned
`pinInvalid`, with one touch-status event and no saved encrypted marker.
Stopped further PIN submissions. An independent python-fido2 2.2.1 read-only
`get_pin_retries` query found one key and reported six remaining attempts
(power-cycle state absent). The query did not submit a PIN or alter settings.

Re-ran the synthetic terminal and binary FFI input tests; all seven passed.
This checks the synthetic input path, not the correctness of the user's PIN.
Asked whether the user typed the configured FIDO2 PIN or only touched the
key, since OTP slot output can otherwise be typed into a terminal prompt.
Live enrollment and decryption remain unverified. No reset or PIN changes
were performed, and no additional PIN attempt was started automatically.

## macOS hardware enrollment and fresh-process decryption verified — 2026-09-30

After clarification that the existing FIDO2 PIN must be typed before touching
the key, the user completed the standalone Dart hardware test over USB.
The user reported that the previous PIN attempts had consisted only of touching
the YubiKey; no actual typed PIN or OTP was inspected by the agent.

- Enrollment process PID 72091, started 2026-09-30T21:16:57.018989Z:
  public receipt `operation=enroll`, `state=success`, `touchRequests=3`,
  `error=null`, `saved=true`.
- The test script waited for enrollment to exit, then launched a fresh process
  PID 73444, started 2026-09-30T21:17:06.462473Z:
  public receipt `operation=unlock`, `state=success`, `touchRequests=1`,
  `error=null`, `saved=true`.

The ordinary `Keypass.hardware` constructor and libfido2 FFI route created a
hardware credential, obtained matching secret outputs from two separately
verified assertions, and saved an HKDF/AES-256-GCM encrypted marker. The next
process reloaded the persisted hardware binding, evaluated the same credential,
authenticated/decrypted the marker, and saved updated authenticator state.
The CLI is a standalone Dart AOT executable; no browser, HTTPS helper, AASA,
provider app host or Keypass service was involved.

Tested hardware remains the connected YubiKey 5-series NFC-capable device,
firmware 5.4.3, through USB on macOS 26.2 arm64. This verifies the core flow
for this device/host. It does not establish USB removal/reinsertion, physical
cancellation/retry, Linux device access, phone NFC/USB, Windows, offline/network
isolation, recovery policy, or Keybay integration. Those gates remain open.

The encrypted marker and public receipts are retained under
`build/hardware/demo/encrypted-test.json` and its receipt companions.
No PIN, OTP, credential payload or PRF output was read from the files or
printed by the agent. No further prompt was launched after successful unlock.

## iPhone NFC hardware implementation and packaged build — 2026-09-30

Implemented `native/hardware_apple` with pinned YubiKit Swift 1.4.0
(revision `e19212f2efbca9af280e57542e669885de5acdc1`) and standard FIDO CTAP
over Core NFC. No vendor ID, serial-number query, management applet or AAGUID
allowlist is used. Hardware eligibility depends on extensions and verification
capabilities; generic implementation does not qualify every hardware vendor.

The adapter uses the existing hardware binary FFI contract and v3 binding.
Discovery is prompt-free and returns the NFC reader, not a discovered key.
PIN-based keys use a capability scan, closed NFC sheet for app PIN entry, then
a second scan. Background/cancel/timeout closes the session before reuse.
Enrollment requires resident credentials, hmac-secret and credProtect=3; its
native attestation profile currently accepts packed ES256 certificate or self
signatures. Dart verifies subsequent assertions before exposing secret bytes.
No PIN retry/reset or fallback is automatic.

Executed locally on macOS arm64 with Swift 6.3.3:

- All 143 Dart tests passed, including NFC event ordering and isolated hardware
  import's namespace/route validation and non-overwrite behavior.
- All 8 Swift bridge/protocol tests passed: arbitrary-vendor GetInfo handling,
  standard FIDO SELECT/APDUs, absent-capability rejection, packed self-attestation
  challenge/tampering checks, binary frame ownership, cancellation/late secret
  rejection, timeout-cause preservation, malformed metadata and unchanged salt.
- The malformed-metadata test caught Foundation's Objective-C exception for
  unsupported JSON values; serialization now checks `isValidJSONObject` first.
- Dart analysis and Flutter demo analysis passed.
- Swift package compilation passed for arm64 iOS 18 simulator; NFC operations
  themselves cannot run in the simulator.
- The signed Flutter iPhone release app built successfully (23.5 MB). Its
  signature verification passed and signed entitlements include NFC `TAG` plus
  the preexisting provider association. All six hardware ABI symbols were
  present in the executable. Swift package source is linked directly; no
  Flutter passkey plugin or method-channel transport was introduced.

Installed the release update on the paired iPhone 16, bundle
`dev.keypass.providerDemo`, preserving app data. Copied the existing 697-byte
Mac hardware marker to `Documents/hardware-import.json`; the source was not
changed. The new screen imports into a separate hardware-test directory and
uses ordinary `Keypass.hardware` with private PIN UI and public-only receipts.
The initial remote launch was rejected because the phone was locked. The user
was given unlock/import/NFC steps. No physical NFC decryption result has been
observed at this checkpoint; installation and compilation are not that proof.

Important scope: SDK immutable PIN/token/PRF copies cannot be completely wiped
by this adapter. Owned mutable copies and FFI frames are cleared, and YubiKit
tracing is disabled. Memory review, certificate-attestation fixture coverage,
on-key biometric hardware, physical cancellation/loss, other vendors, Android
hardware and wired iPhone USB remain unqualified or unimplemented as noted in
the [roadmap](implementation-plan.md). The simulator result does not change that.

Final cleanup before handoff: completed NFC output is also cleared if cancellation
arrives while the sheet is closing; missing hmac-secret output maps to
`prfUnavailable`. The 8 native tests, simulator compilation and signed iPhone
build passed again, and the final release update installed at 17:58 local time.
Physical NFC decryption is still awaiting the user-run test; a public-receipt
copy attempt timed out connecting to the device and yielded no test result.

## Physical Mac USB to iPhone NFC recovery — 2026-10-01

Read the iPhone demo's public hardware receipt after the user completed the
NFC flow. It reports successful authenticated decryption:

- Client: ordinary `Keypass.hardware`, hardware route, NFC transport.
- Namespace: `dev.keypass.hardware-demo`.
- Process: PID 31460, started `2026-10-01T15:18:55.865476Z`.
- Operation: `unlock`; `busy=false`, `saved=true`, `code=null`.
- Two NFC scans and one PIN prompt.
- Status: `Success: the saved marker decrypted over NFC with the original encryption secret.`

The preceding setup copied the retained Mac-created ciphertext into the app's
staging file and provided an import action into separate hardware storage.
The success path awaits assertion verification, HKDF derivation, AES-GCM
authentication/decryption against that binding, and saving updated state before
writing success. This is encryption-recovery proof for the tested YubiKey over
Mac USB and iPhone NFC, not merely a successful scan or sign-in.

The public receipt is retained locally at
`build/hardware/demo/iphone-nfc-receipt-20261001.json`. Only this receipt was
read from the device; no PIN, raw PRF, credential payload or private UI was
inspected. No additional ceremony was launched.

Scope: one YubiKey 5-series device (previously probed firmware 5.4.3) and the
paired iPhone 16. This verifies the core same-credential USB-to-NFC path.
Separate iPhone restart recovery, cancellation/retry, connection loss, NFC
enrollment and other vendors remain unqualified. Android, Windows and Keybay
integration are unchanged by this result.

## Android USB/NFC hardware implementation — 2026-10-01

Implemented the separate native/hardware_android Kotlin/JNI module with
YubiKit FIDO 2.9.0 (reviewed source revision
b4a2f1280f3cd325ba4b431f07cb3323baca4db1). Generic Android USB HID and NFC
IsoDep connections provide discovery and transport; the vendor-specific
Android discovery/UI module is not used. No vendor ID or AAGUID allowlist.

Both transports preserve the existing v3 binding and already-normalized PRF
salt. Required verification, capability checks, packed ES256 attestation
validation, binary PIN/secret transport, bounded cancellation, Activity
ownership and connection cleanup are implemented. PIN input occurs between
closed device sessions and is never retried automatically.

Executed locally on macOS arm64:

- Android release AAR built with arm64-v8a, armeabi-v7a, x86 and x86_64 JNI
  libraries, using NDK 28.2.13676358 and CMake 3.22.1.
- Four JVM tests passed: arbitrary-vendor FIDO GetInfo/standard APDUs and
  capability rejection, bounded request parsing with unchanged PRF salt,
  FIDO HID descriptor validation, and packed self-attestation signature
  binding/tampering/required-verification checks.
- C++ broker tests passed with AddressSanitizer and UndefinedBehaviorSanitizer:
  cancellation does not reuse the slot before worker drain, late/completed
  cancelled secrets are discarded, malformed secret lengths fail closed,
  and returned frames own their data.
- All 143 Dart tests passed; SDK and Flutter demo analysis passed.
- CI configuration now includes the Android hardware AAR, JVM tests and
  native broker sanitizer test. No remote CI execution is claimed.

Attached device identified through adb: Pixel 6a, Android 16, with NFC and
USB host features. These feature flags do not prove FIDO/PRF behavior.
The demo includes ordinary Keypass.hardware and selects a transport per
explicit operation. The retained Mac fixture is the intended cross-transport
test; no new credential or reset is needed.

An initial debuggable-release experiment built but crashed before Dart startup:
Flutter packaged a JIT snapshot with its precompiled engine. The opt-in release
override was removed; the device test uses the ordinary debug/JIT build so
scoped adb run-as can stage ciphertext and read only public receipts.
Normal release configuration stays unchanged. Neither the initial build nor a
debug-device result is AOT/release qualification. Only disposable test data
belongs in this demo.

Physical Android decryption, restart, cancellation, USB permission behavior
and enrollment are pending at this checkpoint. Android OS-provider testing
remains deferred. Further iPhone checks are deferred at the user's request.
JVM/SDK internal or immutable PIN/secret copies cannot be completely cleared;
owned mutable buffers are wiped and SDK tracing is suppressed. Other brands
and production consumer packaging remain separate qualification gates.

Android demo startup follow-up: the standard debug APK built successfully
(91,406,868 bytes) and installed on the Pixel 6a while preserving the staged
Mac ciphertext. Public receipt from PID 19584, started
2026-10-01T16:13:55.826032Z, reports ordinary Keypass.hardware, operation=check,
busy=false, saved=false, code=null, scans=0 and pinPrompts=0:
Hardware host ready. This confirms the packaged JNI/FFI discovery path runs;
no physical-key ceremony or authenticated Android decryption has completed yet.
The 697-byte Mac fixture was copied into app_flutter/hardware-import.json
without printing its contents or changing the source. Import/unlock is ready
for the user. The host test uses JIT/debug, not production AOT qualification.

## Android first NFC attempt and reader handoff — 2026-10-01

The user's first Pixel scan opened a YubiKey validation website. The public
receipt in PID 19584 reports operation=unlock, saved=true, busy=false,
code=deviceUnavailable, scans=1 and pinPrompts=0. The import succeeded, but
this is not Android decryption proof. No PIN verification was attempted.
The website is consistent with normal NDEF/OTP URL dispatch; its URL/content
was not inspected, so the precise site transaction is not asserted.

Inspection found that the adapter emitted presentKey before installing Android
reader mode, and disabled reader mode without suppressing redispatch of the
tag still in range. Scan readiness is now emitted after enableReaderMode.
After connection cleanup, NfcAdapter.ignore(tag, 500, null, null) suppresses
redispatch of that tag until removal before reader mode is disabled. This uses
Android's generic API and changes no key configuration. The underlying first
connection loss and effectiveness of the handoff correction require a retry.
Android documents limitations of ignore for unstable contact/random tag UIDs:
https://developer.android.com/reference/android/nfc/NfcAdapter#ignore(android.nfc.Tag,int,android.nfc.NfcAdapter.OnTagRemovedListener,android.os.Handler)

The NFC handoff update passed the Android debug build (48 seconds) and installed successfully. The reopened app, PID 25671 at 2026-10-01T18:27:01.225753Z, reports hardware host ready, saved=true, busy=false and code=null. The imported ciphertext remains preserved. A physical retry is still required; startup is not recovery proof.

## Physical Mac USB to Android NFC recovery — 2026-10-01

The Pixel 6a / Android 16 public receipt confirms authenticated decryption of
the retained Mac-created marker with the same physical YubiKey over NFC:

- Ordinary Keypass.hardware constructor through Kotlin/JNI and Dart FFI.
- Namespace dev.keypass.hardware-demo; route hardware, transport NFC.
- PID 25671, started 2026-10-01T18:27:01.225753Z.
- Operation unlock; busy=false, saved=true, code=null.
- Two NFC scan prompts and one PIN prompt.
- Success: the saved marker decrypted via NFC with the original encryption secret.

The success path awaits independent assertion verification, HKDF derivation,
AES-GCM authentication/decryption and persistence of updated authenticator state.
This is same-credential cryptographic recovery across Mac USB, iPhone NFC and
Android NFC for the tested key, not just reader detection or sign-in. The Android
host is a standard debug/JIT Flutter demo; Keypass remains Flutter-free.
The public receipt is retained at build/hardware/demo/android-nfc-receipt-20261001.json.

This attempt passed after the NFC handoff change. It does not establish the
precise cause of the earlier connection loss or every NDEF redispatch scenario.
Only the public receipt was read; no PIN, PRF, credential payload or private UI
was inspected. Android fresh-process repetition, USB, cancellation/backgrounding,
NFC enrollment, other vendors and production AOT packaging remain separate gates.
Android OS-provider qualification and Keybay integration are unchanged.


## Consumer SDK and ownership refactor — 2026-10-02

The named system/hardware clients, owned results, opaque records and migrated
consumers are implemented. The [SDK review receipt](reviews/sdk-consumer-api.md)
records checks and remaining qualification boundaries. Local checks passed 157
Dart tests, 25 Node tests, clean Dart/Flutter analysis, standalone AOT consumers,
and the platform native checks listed there. No new device ceremony was run and
no saved physical-provider fixture was changed. Prior v2/v3 encodings and
ciphertext AAD are covered by compatibility regressions.
