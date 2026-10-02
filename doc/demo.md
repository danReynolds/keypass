# Interactive demo and platform test hosts

Two test hosts are implemented: the original macOS AppKit/AOT-worker app and a
[shared provider app](../demo/provider_app/README.md) for iOS, Android and macOS.
The shared app uses Flutter only as the test embedder and calls the ordinary
Keypass API over in-process native FFI. The SDK remains Flutter-free.
Both hosts provide create, unlock and cancel controls. It saves only a public binding and an AES-GCM encrypted test
marker. Enrollment requires two equal verified PRF evaluations. Unlock decrypts
the earlier marker and authenticates updated binding state before saving it.
This is a disposable test, not a Keybay vault or stable storage format.

| Platform | Current runnable app |
| --- | --- |
| macOS | Signed release FFI app: normal-constructor enrollment, restart decryption and cancellation/retry verified; original AppKit fixture retained |
| iOS | Signed release provider app on a physical iPhone; diagnostic enrollment, restart decryption and cancellation/retry verified |
| Android | Release provider APK passed emulator JNI/FFI connection checks; real-provider/device qualification pending |
| Windows | Native DLL build; no demo app yet |
| Linux / unsigned macOS CLI | Historical browser probe; accepted hardware-key demo still to build |

## Shared in-process provider app

See [provider app setup and controls](../demo/provider_app/README.md). Its private
storage is separate from the original macOS demo, preserving that enrolled
credential. Apple and Android association metadata is deployed as an isolated
test fixture. Connection/build results and real-provider outcomes are recorded
separately in [validation](validation.md).

## Original AppKit macOS demo

This checkout's demo now uses `keypass-demo-20260929.web.app`, with a matching
`dev.keypass.demo` Apple app ID under team `5AHFA9FUZG`. The public association
file is deployed on a dedicated Firebase Hosting project with billing disabled.
Apple's CDN returned the correct association. Xcode automatically created the
Associated Domains development profile, valid until 2027-09-29.

Build with automatic provisioning and open the configured demo:

```sh
sh tool/build_provisioned_macos_demo.sh
open "build/demo-signed/Keypass Demo.app"
```

For a public progress receipt, include the launch environment variable (quit
an existing instance first so the new process receives it):

```sh
open --env "KEYPASS_DEMO_RECEIPT=$PWD/build/demo-signed/macOS-receipt.json" \
  "build/demo-signed/Keypass Demo.app" --args --check
```

This launches only a connection check. The receipt path is optional; without
it an earlier receipt file remains stale. Provider approval stays manual.

The script uses the public settings in `demo/apple/demo.env`, an Apple developer
account already signed into Xcode, Dart, and Ruby's `xcodeproj` gem. It permits
Xcode to register/update the demo app ID, profile and this development device.
Override the environment values for a different team's setup, and publish the
matching association before trying credentials. `KEYPASS_DEMO_RUBY` selects a
specific Ruby runtime if needed. The script does not deploy hosting changes.
See [hosting configuration](../demo/hosting/README.md) for the one-file deployment.

The original provider-free build remains useful without a developer account:

```sh
sh tool/build_macos_demo.sh
open "build/demo/Keypass Demo.app"
```

Without domain configuration, **Check connection** exercises the AppKit host,
private transport and Dart native backend without calling a credential provider.
Create/unlock remain disabled. This mode needs no Apple account, entitlement or
published site. It uses an ad-hoc signature and proves no PRF behavior.

Quit the demo before rebuilding it with a real RP identity:

```sh
KEYPASS_DEMO_DOMAIN=your.domain.example \
KEYPASS_DEMO_TEAM_ID=YOUR_TEAM_ID \
KEYPASS_DEMO_SIGN_ID='YOUR_APPLE_SIGNING_IDENTITY' \
KEYPASS_DEMO_PROFILE=/path/to/matching.provisionprofile \
sh tool/build_macos_demo.sh
```

The default bundle ID is `dev.keypass.demo`; override `KEYPASS_DEMO_BUNDLE_ID`
when using a provisioned app identifier. The signing/profile must authorize
Associated Domains for that app. Publish the matching webcredentials AASA entry
on the selected RP domain as described in [Apple setup](../native/apple/README.md).
Do not reuse another app's provisioning identity simply to make this demo launch.
The configured demo now has its own matching profile, created through Xcode
automatic signing; unrelated app profiles are not used.

Once configured, the user selects **Create test passkey**, chooses a provider,
and completes creation plus two verification prompts. Creation is disabled when
a saved test already exists. Quit/reopen the app, then select **Unlock saved
test**. A successful decryption proves continuity of the encryption material.
Do not inspect/automate UI while the user handles a biometric prompt.

The marker lives under `~/Library/Application Support/Keypass Demo/DOMAIN/`.
A derived key exists briefly in memory while the finalized enrollment binding is
authenticated as encryption AAD; it is destroyed afterward. Raw PRF bytes never
enter JSON, argv, logs or a saved file. Erasure is limited to owned buffers; the
runtime and OS/provider may maintain their own allocations.

## Host architecture and proof boundary

This test host is Flutter-free. AppKit owns its main-thread window and invokes
the same native C ABI as the Dart FFI transport. A bundled AOT Dart worker uses
`keypassWithBackendFactory` and `NativePasskeyBackend` through a demo-only private pipe
transport. The worker checks original native ceremony evidence, repeatability,
backup/counter state and signatures before accepting PRF material. The parent
writes the native binary secret buffer directly into an inherited pipe and frees
it; the worker drains and clears its input buffers. There is no loopback server.

This arrangement tests native provider + shared Dart SDK behavior without
requiring an embedded Dart engine inside AppKit. It does not qualify a packaged
in-process Dart/FFI consumer, and the demo pipe transport is not a new public
backend. The shared Flutter test host now supplies the separate in-process embedding
check on macOS/iOS/Android; its existence alone does not qualify a provider.

The initial 2026-09-29 local run passed the provider-free **Check connection**
and visual inspection. A later run configured HTTPS hosting and Apple signing.
See [validation](validation.md) for the latest execution evidence; setup and
connection checks alone do not prove native provider PRF/restart behavior.
