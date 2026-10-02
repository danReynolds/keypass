# Direct hardware keys

The desktop Dart hardware route uses libfido2 through a C++ polling FFI adapter.
This adapter provides USB on macOS/Linux. Separate Apple and Android modules
provide phone transports; see [platform setup](../../doc/platforms.md).

```dart
final passkeys = Keypass.hardware(
  rpId: 'dev.example.vault',
  displayName: 'Example Vault',
  requestPin: requestPinFromUser, // Your UI returns owned writable UTF-8 bytes.
  onEvent: showHardwareInstruction, // Your UI displays informational events.
);

final result = await passkeys.create(label: 'Personal vault');
try {
  // Consume result.secret and persist result.record with encrypted data.
} finally {
  result.dispose();
}
```

Use the same `check()`, `create()` and `unlock(record)` methods as the system route.
The client has no disposal method. The RP ID is a stable DNS-shaped identifier;
direct hardware requires no website and does not authenticate the requesting
executable. Another local client may request the same RP; user verification and
presence are still required by the enrolled credential's policy.

## Build and run

Install libfido2 >=1.16 (tested with 1.17.0), OpenSSL 3, CMake, pkg-config and a C++17 compiler. On macOS, Homebrew provides these dependencies. Linux additionally needs libudev development headers when building libfido2. CMake downloads a checksum-pinned nlohmann/json header.

```sh
cmake -S native/hardware -B build/hardware -DCMAKE_BUILD_TYPE=Debug
cmake --build build/hardware
ctest --test-dir build/hardware --output-on-failure
dart compile exe tool/hardware_demo.dart -o build/hardware/keypass-hardware-demo
build/hardware/keypass-hardware-demo check
build/hardware/keypass-hardware-demo enroll build/hardware/demo/marker.json
build/hardware/keypass-hardware-demo unlock build/hardware/demo/marker.json
```

The demo asks for the key's existing PIN with terminal echo disabled. Enrollment needs registration and two fresh secret evaluations, so expect multiple touches. The demo retains a PIN only for that explicit operation and clears it afterward; the SDK does not cache PINs. The marker contains encrypted disposable test data and public binding metadata. Its companion `.receipt.json` contains only operation status, process ID, touch count, and error code.

Place `libkeypass_hardware.dylib` / `libkeypass_hardware.so` beside the compiled executable, or link its exported symbols into the process. For development under `dart run`, use `--define=KEYPASS_HARDWARE_LIBRARY=/absolute/path/to/library`. Native dependency packaging and automatic Dart build hooks remain a separate milestone; this currently requires installing or bundling libfido2 and its dependencies.

On Linux the application needs permission to access the USB HID device, usually through distribution-provided FIDO udev rules. Do not run the application as root to bypass missing permissions.

## Security contract

- Require FIDO2, `hmac-secret`, resident credentials, user verification, user presence, and `credProtect=3`. No U2F or prompt-only fallback.
- PIN failures return a typed error after one attempt. There is no PIN guessing, automatic retry, PIN setup/change, reset, credential deletion, or credential enumeration.
- Prefer configured on-key user verification; otherwise obtain the existing PIN through the application's callback. Cancellation is forwarded while waiting for that callback and during the native ceremony.
- Native libfido2 verifies registration attestation against the fresh request hash. This checks the signature, not the manufacturer's certificate chain or device provenance.
- Dart independently checks RP hash, UP/UV flags, credential identity, ES256 assertion signatures, the signed extension, backup state, and signature-counter policy before releasing a secret.
- Normalize each PRF input exactly once using `SHA-256(UTF8('WebAuthn PRF') || 0x00 || input)` before passing it as the CTAP `hmac-secret` salt.
- Raw PINs and 32-byte secrets cross a binary FFI boundary, never JSON. SDK-owned mutable buffers are cleared. Dart/native/platform internals may make additional copies; this is not a guarantee that a compromised process cannot read them.
- Enrollment requires two matching results from separate verified assertions before a binding is returned.

## Persistence and selection

Existing provider bindings retain their exact version-2 encoding. Hardware bindings use version 3 with an explicit hardware route, required verification, and transport hints. Routes are checked before opening a provider or hardware prompt. No automatic cross-route fallback or credential replacement occurs.

A ceremony currently accepts one binding. One connected key is selected automatically; multiple connected keys require an application selection callback. Return the exact offered HardwareConnection object. The selected connection is retained through one create/unlock operation, then discarded. Each subsequent operation rediscovers connections; the same client can be reused after reconnecting.

The key may advertise NFC in its persisted transport hints. That is capability metadata, not evidence that this USB adapter implements NFC. The Apple NFC and Android USB/NFC modules are separate adapters. Windows hardware and wired iPhone USB remain unimplemented.

## Validation

`test/hardware` includes independently signed ES256 fixtures, malformed-proof rejection, route isolation, and a compiled FFI fixture covering PIN ownership and cancellation. The native CTest target covers ABI validation, busy state and cancellation. Linux build validation is available with:

```sh
docker build -f tool/validation/hardware.Dockerfile -t keypass-hardware-validation .
```

A container build validates compilation and the no-device path. It does not validate a physical key on a Linux host. Live platform evidence is recorded in `doc/validation.md`.

Dependencies retain their upstream licenses: libfido2 (BSD-2-Clause), OpenSSL (Apache-2.0), and nlohmann/json (MIT). Distributions that bundle them must include their required notices.
