# Implementation plan

Keypass 0.1.0-dev.2 and Keybay 0.2.0 are published. Later source cleanup remains
unreleased. [External review](external-review.md) identifies exact baselines;
[validation](validation.md) holds dated device receipts.

## Accepted scope — 2026-09-29

A Flutter-free Dart library for verified, repeatable passkey-derived encryption
material through two routes:

- OS providers in native app hosts: Apple, Android and experimental Windows.
- Capability-based FIDO2 hardware: desktop USB and phone NFC. Target platforms
  are iOS, Android, macOS, Linux and Windows; implementation/qualification differs.

No vendor allowlists. Yubico libraries implement standard protocols; additional
vendors need qualification. OTP, PIV and key administration are out of scope.
Browser/extension access remains research, outside the public SDK. Keybay owns
its encryption, platform root, persistence and recovery.

## SDK boundary accepted and implemented — 2026-10-02

[SDK usage](sdk.md) defines `Keypass.system/hardware`, `check`, `create/unlock`,
opaque records and disposable results. The client configures an explicit RP ID;
it does not open a session. Desktop USB dependencies use Dart build hooks.
Mobile and OS-provider consumers configure their native hosts separately.

## Runtime independence constraint

No enrollment or recovery path may require a Keypass-operated website, API,
relay, account or registry. Apple/Android system routes use the consumer's
associated domain; the demo's hosted association files are test fixtures only.
Windows has no equivalent domain-association enforcement. Direct hardware uses
a stable RP namespace, which does not authenticate the requesting executable.
A user's chosen provider may have its own network/account requirements.

## 0. Existing foundation

Implemented: standalone Dart API, typed errors, cancellation, result ownership,
bounded ceremony verification, fresh challenges, required user verification,
repeatability checks and persisted authenticator state. Native adapters, test
hosts and synthetic rejection/ownership tests exist.

The [evidence table](external-review.md#evidence-and-open-work) separates observed
decryption from builds and smoke tests. API and record formats remain experimental.

## 1. Finish OS-provider qualification

Observed: macOS normal FFI enrollment, restart decryption and cancel/retry;
iPhone diagnostic-host enrollment, restart decryption and cancel/retry.
Flutter is only the demo host; the library uses native FFI.

Remaining:

- [ ] iOS undecorated production constructor, background/lifecycle and provider
  matrix. Diagnostic timing does not explain the earlier repeated-prompt report.
- [ ] Broader macOS lifecycle/provider coverage. The original worker-host timeout
  remains unexplained despite successful normal FFI recovery.
- [ ] Android Digital Asset Links for deliberate signing identities; real
  provider PRF, restart decryption, Activity lifecycle and release shrinking.
- [ ] Windows packaged consumer with a real owner window and provider. Build
  evidence exists, but no packaged runtime qualification is claimed.

Acceptance: enrollment and fresh-process authenticated decryption; wrong
context, missing verification/PRF, cancellation and late callbacks release no
secret. Provider availability alone is insufficient.

## 2. Add the hardware route

Implemented: route-bound v3 records, normalized PRF inputs, required user
verification, capability checks, typed PIN/device/storage errors and explicit
connection selection. USB/NFC transport changes must preserve credential identity.

| Adapter | Implemented | Observed physical evidence |
| --- | --- | --- |
| macOS/Linux USB | libfido2 C ABI and Dart FFI, PIN/touch/selection UI, cancellation, CLI | macOS YubiKey 5.4.3 enrollment and fresh-process marker decryption |
| iOS NFC | YubiKit Swift protocol layer, standard FIDO AID, binary FFI and lifecycle handling | Same Mac-created credential decrypted the marker on iPhone NFC |
| Android USB/NFC | YubiKit FIDO protocol layer, generic HID/IsoDep connections, Kotlin/JNI | Same credential decrypted the marker on Pixel 6a NFC in debug/JIT |
| Windows hardware | Not implemented/qualified | None |

Remaining:

- [ ] Physical Linux USB, device permissions and packaged consumers.
- [ ] Desktop unplug/reconnect, wrong/multiple keys, PIN blocking, full storage
  and cancellation/retry; additional vendors and firmware.
- [ ] Phone NFC enrollment, fresh-process repeats, connection loss and lifecycle
  failures; Android USB and production AOT packaging.
- [ ] Windows OS-mediated physical-key route with normal user privileges.
- [ ] Desktop NFC readers/drivers. Wired iPhone USB is unimplemented.

Acceptance: create on desktop, decrypt after restart/reconnect, then recover the
same marker over supported phone NFC paths. Failure never falls back to software
material, resets a key or deletes unrelated credentials. No automatic PIN retries.

## 3. Consumer packaging and API completion

Implemented: explicit RP-scoped API, desktop JIT/AOT hooks and relocated-bundle
tests, CLI interaction/cancellation, documented native setup and format rejection.

- [ ] Broaden packaged consumer checks across remaining hosts. Signing, native
  dependencies, UI lifecycle and permissions are application responsibilities.

## 4. Keybay integration

Shipped: explicit `auth.add` enrollment, authentication-only `open`, alternative
methods, mandatory platform root, atomic add/list/remove, key rotation and
prompt-free record operations. [Integration](keybay-integration.md) describes
ownership; [Keybay release records](https://github.com/danReynolds/keybay/blob/main/doc/release-readiness.md)
identify artifacts and format compatibility.

- [ ] Physical multi-key recovery/loss, auth-change interruption and lifecycle
  coverage. Installed CLI success does not complete that matrix.
- [ ] Release Keypass source cleanup, then update Keybay's published dependency.
  Keybay currently pins 0.1.0-dev.2, not this repository's main branch.

## 5. Release qualification

- [ ] Record provider, device/firmware, OS, packaging and transport per claimed
  configuration; repeat fresh-process and fresh-transport recovery.
- [ ] Test sync/offline behavior separately where claimed.
- [ ] Cover cancellation at each stage, late native results, host loss,
  interruption, PIN lockout and multiple keys.
- [ ] Independent security review of verification, PRF binding, identity,
  memory/ownership and consuming envelopes before freezing formats.

## Execution order

Prioritize hardware failure/recovery checks and remaining platform packaging,
then broaden provider/device coverage and complete external review. Android
provider testing and further iPhone checks were deferred by the user.

Physical checks require explicit participation for PIN, biometric and touch
approval. Do not inspect provider UI while the user handles a prompt or start
a ceremony just to check progress. Dated [research](research/2026-09-29-cli-passkey-access.md)
and receipts are historical; this plan records current scope and remaining work.
