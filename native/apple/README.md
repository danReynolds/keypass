# Apple native adapter

For an interactive macOS test app, see the [demo guide](../../doc/demo.md).

`Keypass.swift` implements the binary C ABI in `../include/keypass.h` using
AuthenticationServices. It supports macOS 15+ and iOS/iPadOS 18+. The same source
builds for macOS, the iOS simulator, and iOS devices. This is an experimental
adapter. Exact signed-host enrollment/restart evidence and remaining
qualification gaps are recorded in [validation](../../doc/validation.md).

Add this directory as a local Swift package to the app's Xcode project and link
and embed its **KeypassNative** dynamic product. The package has no Flutter
integration. Dart discovers its exported ABI through `DynamicLibrary.process()`.
For a custom macOS packager, build `libkeypass.dylib` and place/sign it in the
app's `Contents/Frameworks` directory. Do not unload it while Dart is running.
App packaging/signing, rather than Dart pub alone, owns this native dependency.

The host must have a visible AppKit window or one unambiguous foreground UIKit
window scene. The bridge chooses the key/main macOS window, falling back to a
sole visible eligible window. On iOS it presents only from an active scene's
visible normal-level key window. If that window is transitioning after a
provider sheet, the bridge observes scene/window notifications for up to three
seconds and waits for the same window to become active and key. It does not
switch windows or wait through backgrounding/disconnection. Missing or
ambiguous hosts return `hostUnavailable`; no artificial window is created.
All authorization-controller work runs on the main thread. Native cancellation
removes any presentation waiter and produces one response immediately; late
results are discarded and erased.

Configure the Dart client with the RP domain and add the associated-domain
entitlement `webcredentials:YOUR_DOMAIN` to the signed app. Serve this public
JSON at `https://YOUR_DOMAIN/.well-known/apple-app-site-association`:

```json
{"webcredentials":{"apps":["YOUR_TEAM_ID.YOUR_BUNDLE_ID"]}}
```

Use the real app identifier prefix from the provisioning profile when it differs
from the team ID. Association must work before actual enrollment. No API key is
needed. An unsigned `dart run`/CLI reports `hostUnavailable`; linking this library
does not grant it the app's domain authorization.

```sh
swift test --package-path native/apple
sh tool/apple_native_smoke.sh
```

The smoke script runs a macOS app and builds an iOS simulator app. Install the
latter with `simctl install DEVICE build/native/KeypassSmoke-iOS.app`, then launch
`dev.keypass.native-smoke`. Its Documents/keypass-native-smoke.txt receipt covers
presentation discovery, cancellation, malformed requests and busy handling.
It creates no passkeys and is not an encryption/provider qualification test.
`PlatformPrfProbe.swift` remains a historical compile-only SDK probe.
