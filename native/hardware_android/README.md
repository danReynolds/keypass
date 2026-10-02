# Android physical FIDO2 adapter

Standalone Kotlin/JNI adapter for `Keypass.hardware`. It uses Android USB host
and NFC `IsoDep` connections with the released YubiKit FIDO protocol library
2.9.0. It does not use YubiKit's vendor-specific Android discovery or optional
UI module. No USB vendor ID, serial, management applet or AAGUID allowlist is used.
Eligibility is determined by standard FIDO interfaces and CTAP capabilities.
Implementation is not a claim that every key/vendor has been qualified.

## Consumer setup

- Android API 28+, a foreground Activity, and the packaged native AAR plus its
  transitive Gradle dependencies. Supported build ABIs are arm64-v8a,
  armeabi-v7a, x86 and x86_64.
- Include this module as a Gradle project and add `implementation(project(":keypass-hardware"))`.
  The demo's Android settings show the relative project-directory wiring.
  An AAR copied alone does not bundle the YubiKit/AndroidX Java dependencies.
- The merged manifest declares optional NFC/USB-host features and NFC permission.
  AndroidX Startup loads `libkeypass_hardware.so` and registers Activity lifecycle
  callbacks. Preserve its provider and the supplied consumer shrinker rules.
- Supply constructor callbacks for key selection, private PIN entry,
  presentation/touch status and cancellation. Call `Keypass.hardware(rpId:, requestPin:, selectConnection:, onEvent:)`; no Activity handle is passed through Dart.
- The namespace is a stable DNS-shaped credential identifier. Direct hardware
  access requires no Digital Asset Links, HTTPS website, API key or Keypass service.
  This namespace does not authenticate the calling local app.

Availability is prompt-free: it lists an enabled NFC reader and candidate USB
interfaces. It does not scan a key, request USB access or prove hmac-secret.
USB candidates must have an unambiguous 64-byte interrupt input/output profile;
after the OS grants access the adapter validates the standard FIDO HID report
usage page before sending CTAP or requesting a PIN. Non-FIDO candidates fail.
NFC uses the standard FIDO AID and Android reader mode, not a system passkey sheet.
Only one unambiguous resumed Activity can own a ceremony.

## Verification and lifecycle

Both transports feed the same CTAP2 implementation and hardware v3 binding.
The adapter requires hmac-secret, user presence and user verification. Enrollment
also requires a resident credential, credProtect=3 and the packed ES256 attestation
profile (certificate or self signature). Native attestation verification binds the
fresh challenge; Dart independently verifies assertions before releasing output.
Certificate signature validation is not manufacturer trust or a chain policy.

The direct protocol receives the already-normalized 32-byte PRF salt from Dart.
It uses the SDK's PIN/UV protocol and ECDH/cryptography primitives without applying
the high-level PRF extension's normalization again. PIN protocol 2 is preferred,
with protocol 1 supported. No verification downgrade, PIN retry/reset, credential
replacement or software-secret fallback is automatic.

PIN-based operations use two device sessions: check capabilities/retries, close
the connection, collect the existing FIDO2 PIN in app UI, then reconnect to perform
the operation. For NFC remove the key during PIN entry and scan again afterward.
Keep the key in range until the app advances. USB may first show Android's device
permission dialog; that dialog is separate from PIN verification.

Cancellation, a 120-second deadline, and owner Activity loss stop the operation.
The worker closes its own connection before a new operation can reuse the broker.
Late results after cancellation are discarded and their owned buffers cleared.
The OS USB permission dialog's pause is allowed; backgrounding/stopping the owner
still cancels. Physical removal, lifecycle and multi-key behavior require device
qualification in addition to the synthetic/native tests.

## Memory and logging limits

PIN bytes use a separate binary JNI call and are not JSON metadata. Owned PIN,
token, shared-secret, result and FFI buffers are cleared when no longer needed.
Java normalization and SDK internals can retain immutable or internal copies;
this adapter cannot promise complete zeroization of JVM/provider/caller memory.
Consumers must not log PINs, PRF output or raw CTAP payloads.

Before each ceremony the adapter installs a no-op legacy YubiKit logger, which
also prevents its transport tracing from reaching an embedding SLF4J provider.
This affects the shared SDK logger. Do not replace it with a tracing logger during
a ceremony. A future SDK update requires rechecking logging and memory behavior.

## Build and checks

Use JDK 17+ and an Android SDK containing platform 36, NDK 28.2.13676358 and
CMake 3.22.1. From the repository root:

```sh
native/android/gradlew -p native/hardware_android assembleRelease testDebugUnitTest
c++ -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined \
  native/hardware_android/test/broker_test.cpp -o /tmp/keypass-android-broker-test
/tmp/keypass-android-broker-test
```

The protocol tests use synthetic connections and generated attestation evidence;
they do not replace physical USB/NFC checks. See [validation](../../doc/validation.md)
for exact executed evidence and [the demo](../../demo/provider_app/README.md) for
device steps. Native packaging remains manual. Android OS-provider qualification
uses the separate Credential Manager module and is not proven by hardware tests.

Dependency/source review: [YubiKit Android 2.9.0](https://github.com/Yubico/yubikit-android/tree/2.9.0)
(revision b4a2f1280f3cd325ba4b431f07cb3323baca4db1),
[Android USB host](https://developer.android.com/develop/connectivity/usb/host).
YubiKit's Apache-2.0 license and required notices must accompany redistribution.
