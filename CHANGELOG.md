## 0.1.0-dev.2

- Replace the callback-scoped facade with Keypass.system and Keypass.hardware,
  one explicit RP ID, check/create/unlock, opaque PasskeyRecord and owned
  PasskeyResult with synchronous dispose.
- Add HardwareEvent/onEvent and opaque, operation-local connection selection.
- Preserve development v2/v3 records, PRF inputs and verification-state updates.
- Make native backends operation-owned and fence cancellation before result
  transfer; tighten native success publication and late-callback ownership.
- Migrate Dart CLI and native-host demos, preserving saved ciphertext/AAD.
- Document the Keybay consumer boundary without changing Keybay itself.

## 0.1.0-dev.1

- Establish the experimental Flutter-free Dart API and shared lifecycle core.
- Add synthetic tests for binding validation, PRF consistency, cancellation,
  selection, redaction and scoped byte cleanup.
- Record platform implementation and Keybay integration plans.
- Add an isolated browser/unsigned-CLI probe with paired encrypted handoff,
  ES256 browser checks, restart marker and synthetic interoperability tests.
- Redact browser provider diagnostics and clear late secret results after prompt
  cancellation; test saved-credential reuse without replacement enrollment.
- Expire browser credential actions with the authenticated CLI session deadline.
- Add independent Dart ES256/none WebAuthn verification with bounded CBOR/JSON
  parsing, strict P-256/DER checks, signed adversarial vectors and raw browser
  evidence verification before using the PRF result.
- Validate analyzer, 85 Dart tests, 25 Node tests and AOT compilation on macOS
  and Linux ARM64 Docker; real Linux desktop/provider support remains untested.
- Add Apple AuthenticationServices, Android Credential Manager/JNI, and Windows
  WebAuthn adapters behind a shared binary FFI transport and Dart verifier.
- Resolve app presentation hosts automatically; package a Swift product, Android
  AAR with Startup bootstrap, and a Windows DLL build.
- Persist backup/counter verification state in experimental binding encoding v2;
  callbacks expose updated state for atomic consumer persistence.
- Add native host smoke fixtures and binary ownership/cancellation tests. Native
  provider/device support remains unqualified; browser SDK wiring is pending.
- Add explicit hardware enrollment/evaluation through a libfido2 USB adapter on
  macOS/Linux and a standalone Dart encrypted-marker demo.
- Preserve provider v2 bindings and add route-bound hardware v3 bindings with
  required verification, transport hints and WebAuthn-compatible PRF inputs.
- Add binary PIN callbacks, explicit key selection, cancellation/draining, and
  25 hardware tests. Native packaging and other hardware platforms remain open.
- Fix terminal PIN input cleanup ordering and preserve input/cancellation
  regressions with an isolated pseudo-terminal fixture.
