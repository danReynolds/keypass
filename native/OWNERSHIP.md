# Native operation ownership

The Dart SDK owns a fresh backend for each create, unlock, or availability
operation. Native host installation and the loaded library may remain
process-wide; connection choice, PINs, presentation ownership, cancellation
identifiers, and verification work belong to the individual operation.

A successful terminal frame transfers one binary PRF allocation to Dart.
Before that frame can be polled, Keypass-controlled device connections,
provider presentation ownership, and secret-bearing worker temporaries have
been released or cleared. Dart copies the binary result, invokes the native
wiping free function, completes its remaining operation cleanup, and only then
returns the caller-owned result. Disposing that result clears the Dart-owned
secret; it does not need to cancel or dispose a native operation.

This contract covers explicitly owned mutable buffers, not every runtime copy.
Android Credential Manager supplies immutable JSON containing PRF output, and
JSON/base64 parsing can create additional immutable string temporaries. Apple
AuthenticationServices and the third-party protocol SDKs may retain internal
copies. These are never logged or persisted as a fallback; the SDK cannot
promise their erasure.

## Success handoff

- Apple provider results remain unpollable while their controller/delegate is
  being torn down. The presentation gate also prevents a subsequent request
  from moving to another window while the original scene is transitioning.
- Windows success remains unpollable until WebAuthn result owners have been
  destroyed and the cancellation watchdog has joined.
- Android JNI completion consumes its mutable Java secret array, copies it to
  the native frame, and clears the temporary native copy while holding the
  publication lock. Poll cannot observe a success before those copies clear.
  The hardware worker closes its transport and retires Activity ownership
  before invoking completion.
- Apple hardware completion consumes and clears the worker response before
  publishing its packet. NFC session cleanup precedes completion.
- Desktop libfido2 completion publishes only after the synchronous device
  operation and its device/assertion owners have left scope.

## Cancellation and late callbacks

Cancellation is not proof that an operating-system UI has finished. Apple and
Windows can return a cancellation error promptly while retaining a shared busy
guard until the framework callback or blocking OS call completes. Android
likewise retains its active provider operation until Credential Manager calls
back. A late callback carries its original operation ID, has no authority to
publish a successful result, and cannot retire a newer operation.

If an OS provider never acknowledges cancellation, that provider remains busy
rather than permitting overlapping ceremonies. The SDK cannot force the OS
callback to run; host lifecycle/device qualification must cover this boundary.
A process restart clears the process-local guard, not any provider credential.

Direct hardware cancellation waits for transport cleanup before reusing the
native slot. A bounded Dart transport failure may report an error if a broken
native worker never drains; the native guard must still prevent slot reuse.
No failure releases a secret or switches to another credential.

Application PIN/selection callbacks are a separate boundary. Dart cancels their
prompt signal and fences late completion, including clearing any late PIN
buffer. The SDK cannot force an arbitrary consumer Future to settle and must
not wait forever for one. Applications should close their prompts when their
signal is cancelled. This does not grant a late callback authority over the
next native request.
