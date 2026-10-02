# Keypass provider qualification app

A disposable Flutter test host for the standalone Dart SDK. Create encrypts a
marker only after two verified PRF evaluations agree. Unlock authenticates and
decrypts the saved marker, then persists updated authenticator state. Quit/reopen
before unlocking to test process-independent recovery.

By default this host uses the ordinary `Keypass.system(rpId:)` constructor and native FFI
backend, with no diagnostic wrapper or receipt writes between provider requests.
The optional Dart define `KEYPASS_DEMO_PROGRESS=true` enables the demo-only
backend decorator: numbered steps and fixed operation/phase labels. It forwards
each call once and never exposes payloads to its reporter. Its awaited receipt
writes can affect timing, so qualify the default path separately. The public
receipt names the construction mode; provider counts are null when disabled.

The Swift adapter is linked into the Apple executable; the Android Gradle module supplies JNI and
Credential Manager. There is no Flutter passkey plugin, method channel for
passkeys, browser helper, or private AOT-worker transport here. `path_provider`
is a demo-only dependency for the app's private storage directory.

The shared `lib/store.dart` is Flutter-free and also used by the original macOS
AOT-worker demo. Its format remains compatible with that demo, but this app uses
a separate storage directory and never imports or overwrites the earlier marker.

## Run

From this directory, with Flutter on PATH:

```sh
flutter pub get
flutter analyze
flutter run -d macos --release
flutter run -d YOUR_IOS_DEVICE --release
flutter run -d YOUR_ANDROID_DEVICE --release
```

For first-time Apple provisioning, open the relevant Runner Xcode workspace and
use automatic signing, or run `xcodebuild` with `-allowProvisioningUpdates` and
`-allowProvisioningDeviceRegistration`. Xcode must have the authorized team's
developer account. Local release builds retain/export the Swift C ABI for Dart
FFI. The checked-in projects contain the source reference; regenerating it uses
`ruby ../../tool/configure_provider_demo.rb` with xcodeproj 1.27 or newer.

Apple deployment targets are iOS 18 and macOS 15. Android minimum SDK is 28,
using the native adapter's Gradle 8.10.2 / AGP 8.8 / Kotlin 2.1 build generation.
Android release APKs use the deliberately associated local debug certificate
for this demo only. They are not production signing configurations.

Identity and public association deployment are documented in
[demo hosting](../hosting/README.md). `KEYPASS_DOMAIN` is an optional Dart define,
but changing the RP also requires corresponding native entitlement/association
changes. The fixture domain is an app default only, never an SDK default.

## User-controlled test

1. Select **Check connection**. This proves only host/FFI readiness.
2. Select **Create test passkey** and approve registration plus two evaluations.
3. Quit/force-stop and reopen; select **Unlock saved test**.
4. Repeat unlock and cancel from the provider UI; the existing marker must remain.
5. Test provider/background/rotation behavior on physical devices where supported.

Do not automate or inspect the credential UI while the user handles it.

The private app support directory contains
`provider-test/DOMAIN/encrypted-test.json` and `receipt.json`.
The first contains public binding metadata plus AES-GCM ciphertext, nonce and
tag. The receipt contains process/platform/status fields plus fixed provider-call
phase labels, timestamps and request counts when enabled; read it for
progress without inspecting credential UI. Neither file stores raw PRF bytes.

Successful build/connection is not a real-provider or encryption qualification.
[Validation](../../doc/validation.md) records the exact checks completed.

## iPhone hardware test

The iOS app links `KeypassHardwareApple`, using the ordinary `Keypass.hardware`
constructor with no diagnostic backend decorator. Its NFC entitlement, standard
FIDO AID and purpose text are included; signing must provision NFC capability.
See [hardware setup](../../native/hardware_apple/README.md).

Hardware tests use `hardware-test/dev.keypass.hardware-demo/` under app support,
with a separate marker and public `receipt.json`. The provider fixture is preserved.

1. Stage a copy of `build/hardware/demo/encrypted-test.json` into the app's
   `Documents/hardware-import.json` with Xcode/devicectl. Do not print its contents
   or replace an existing saved marker.
2. Open **Test a hardware key over NFC**, then **Import Mac encrypted test**.
3. Select **Unlock saved hardware test**. Scan the same key, type its existing
   FIDO2 PIN when asked, then scan again. Hold it near the top of the phone until
   each NFC sheet closes.
4. Read only the public hardware receipt for progress. Success means
   authenticated decryption passed with the imported binding and ciphertext.
5. Reopen and retry for fresh-process recovery; test cancellation/loss separately.

No new credential is needed to import/unlock. When no import or marker exists,
**Create a new hardware test** permits NFC enrollment. No automatic PIN retry.
The demo's text controller necessarily holds transient immutable strings;
clearing it is not a complete zeroization guarantee. Do not inspect or automate
the PIN/NFC UI while the user handles it.

## Android hardware test

The demo includes the separate hardware Gradle module and uses ordinary
Keypass.hardware through JNI/FFI. No Digital Asset Links are needed for these
direct hardware ceremonies. See [Android hardware setup](../../native/hardware_android/README.md).

Launch directly into the hardware screen with:

    flutter run -d YOUR_ANDROID_DEVICE --dart-define=KEYPASS_DEMO_HARDWARE=true

For device qualification use the ordinary debug/JIT demo so adb run-as can
stage the retained ciphertext and read only public receipts. This is separate
from release/AOT packaging qualification. Do not make the release variant
debuggable: Flutter can then package a JIT snapshot with the release engine.
Never use the debug demo for real vaults or production release qualification.

1. Copy the existing Mac fixture into the app's app_flutter/hardware-import.json
   without printing its contents or overwriting an existing marker.
2. Select **Import Mac encrypted test**, then **Unlock saved hardware test**.
3. For NFC, hold the same key against the back of the phone until the app advances.
   Remove it for PIN entry, enter its existing FIDO2 PIN, then scan again.
4. For USB, connect using the appropriate host adapter. Select the USB candidate
   if asked, allow Android's USB permission request, enter the key's PIN and
   touch it when requested.
5. Read the public receipt at files/hardware-test/dev.keypass.hardware-demo/receipt.json
   through run-as. Restart and retry separately; do not clear data or re-enroll.

Only one transport is used within an enrollment/secret operation. The demo creates
a new client for each explicit operation so another transport can be selected on
the next attempt. A USB candidate is not verified as FIDO until its report
descriptor can be read after permission. Availability never prompts for permission.
Do not inspect or automate PIN or key-presentation UI while the user handles it.
