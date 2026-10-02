# SDK consumer readiness review — 2026-10-02

This change implements the agreed Dart consumer API. It prepares Keypass for a
Keybay integration; it does not modify Keybay's store/envelope implementation or
complete the platform release-qualification roadmap.

## Accepted contract

- One Keypass interface, configured by synchronous Keypass.system or
  Keypass.hardware constructors with an explicit RP ID.
- check(), create(label:) and unlock(record: positional), with optional
  per-operation cancellation. No client session or client disposal.
- PasskeyResult exposes a read-only 32-byte secret and immutable PasskeyRecord.
  Its synchronous, idempotent dispose clears the owned buffer. Caller copies and
  derived keys remain caller-owned.
- Opaque records retain stable identity, RP/route and versioned serialization.
  The existing v2/v3 wire fields and PRF inputs are preserved.
- Hardware callbacks live on configuration: requestPin, selectConnection and
  onEvent with HardwareEvent. Offered connection objects are operation-local.
- The normal import has no Flutter dependency and exposes no backend plumbing.
  Native host linking, permissions, app associations and signing remain explicit
  consumer setup.

## DX and architecture review iterations

Two agent review tracks checked consumer DX and security/ownership against the
accepted design. The implementation incorporated these concrete findings:

1. The original long-lived backend cached the selected device. Every public call
   now creates/disposes an operation backend; selection stays stable through a
   create operation's three ceremonies and is refreshed on the next operation.
2. Native success could become pollable before worker/secret teardown. Windows
   now waits for RAII cleanup and watchdog completion, Apple provider results
   wait for controller teardown, and Android/Apple hardware handoffs clear owned
   temporary buffers before publication.
3. Cancellation is not proof that an OS request has completed. Native busy
   fences retain the old operation until the framework acknowledges it. Late
   callbacks have no authority over later operations. Consumer PIN/selection
   Futures are bounded/fenced rather than awaited indefinitely.
4. The demo uses the full saved record as AES-GCM AAD. Migration preserves the
   original-record decryption followed by updated-record re-encryption. New
   literal-v2/v3 regression fixtures detect accidental codec/AAD changes.
5. The macOS worker borrows a process-wide IPC transport. Its operation backend
   now disposes a borrowed wrapper without closing that channel; repeated
   commands in one worker are covered.
6. Public documentation makes result ownership, Future abandonment, optional
   check()/busy behavior, consumer KDF and authenticated atomic persistence
   responsibilities explicit. No undocumented consumer helper APIs are implied.

The final public-code review and completion audit found no blocking DX or
architecture issue for Keybay consuming this SDK with the documented manual host
setup. This is
an internal engineering review, not an independent cryptographic audit.

## Local evidence

| Check | Result |
| --- | --- |
| Dart formatting and analyze --fatal-infos | Clean |
| Full Dart suite | 157 passing tests, including a full Dart 3.13.5 rerun |
| Node browser-probe suite | 25 passing tests |
| Focused demo/AAD/worker/terminal suite | 23 passing tests, included in full suite |
| Flutter test-host analysis | Clean |
| Standalone hardware CLI and public example AOT builds | Passed |
| Separate pure-Dart consumer using only public package dependency | Offline resolution, analysis, AOT build passed; missing-host check returned backendUnavailable |
| macOS/Linux desktop hardware native CTest on this Mac | 1 passing test |
| Apple provider Swift suite | 7 passing tests |
| Apple hardware Swift suite | 9 passing tests |
| iOS hardware simulator SDK build and provider device SDK typecheck | Passed |
| Android provider cancellation JVM suite and release/smoke build | 2 tests, build passed |
| Android hardware JVM suite and four-ABI release build | 4 tests, build passed |
| Android hardware C++ broker under ASan/UBSan | Passed |
| Windows provider pinned-dependency cross-build | Passed |

The workflow runs the new Android provider tests as well as the existing native
and cross-platform Dart jobs. Remote CI status belongs to the PR checks rather
than this local receipt.

## Remaining qualification boundary

No live device ceremony was run for this SDK refactor. Prior exact receipts
remain in [validation](../validation.md); a rename or synthetic fixture is not
new physical-device evidence. Android OS-provider testing was previously
deferred by the user. Windows direct hardware, wired iPhone USB, additional
vendors/transports, automatic native packaging and broader lifecycle/failure
qualification remain on [the roadmap](../implementation-plan.md).

The supported integration route is the documented manual native host setup.
If a cancelled OS provider never acknowledges cancellation, its guard stays busy
until host restart. Immutable provider/runtime allocations cannot be guaranteed
erased; [native ownership](../../native/OWNERSHIP.md) specifies the boundary.

Keybay remains responsible for purpose-bound KDF, platform-root protection,
encryption envelopes, authenticated record storage, transactional counter
updates, method changes, recovery and revocation.
