# Android native adapter

This Android library builds an AAR containing Kotlin Credential Manager code and
`libkeypass.so` for arm64-v8a, armeabi-v7a, x86, and x86_64. It has no Flutter
or method-channel dependency. Minimum Android API is 28. Credential Manager
and its Google Play Services adapter are pinned to stable AndroidX 1.6.0.

Include this directory as a library module in the consuming Android Gradle
project and add `implementation(project(":keypass-native"))` to the app. Keep
the AAR's transitive dependencies and merged manifest. AndroidX Startup loads
the native library and registers Activity lifecycle tracking automatically.
Dart then loads `libkeypass.so`; ordinary calls require no Activity parameter.
A single resumed Activity is required. Destruction cancels its outstanding
request. Multiple resumed hosts are treated as ambiguous.

The trusted expected WebAuthn origin is computed from the running APK's signing
certificate, independently of provider response JSON. A multi-signer APK is
currently rejected. Rotation and app/provider lifecycle need device qualification.

Configure the Dart client's domain and publish the association at
`https://YOUR_DOMAIN/.well-known/assetlinks.json`:

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls", "delegate_permission/common.get_login_creds"],
  "target": {
    "namespace": "android_app",
    "package_name": "YOUR_APP_PACKAGE",
    "sha256_cert_fingerprints": ["YOUR_COLON_SEPARATED_SHA256_CERTIFICATE_FINGERPRINT"]
  }
}]
```

Use the app signing certificate, including Play App Signing for Play releases.
Authorize debug fingerprints only for a deliberate development association.
No API key is needed. A usable provider and screen lock are runtime requirements;
Android version or `availability().canAttempt` alone does not prove PRF support.

```sh
cd native/android
./gradlew assembleRelease :smoke:assembleDebug
```

`smoke` is a separate disposable app (`dev.keypass.smoke`). Its internal
files/keypass-native-smoke.txt receipt tests actual JNI delivery, Activity
selection and signing-certificate origin without requesting a credential. The
available API 33 AOSP emulator passes this test but has no Google passkey provider.

The provider API supplies an immutable JSON String that can contain PRF output.
The adapter extracts it promptly into a binary byte array, never logs or retains
the JSON, and erases owned arrays/native buffers. Erasing the framework's String
allocation is not possible. Full real-provider enrollment, restart, rotation,
release shrinking, cancellation during UI and device recovery remain unqualified.
