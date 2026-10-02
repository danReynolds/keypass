# Windows native adapter

`keypass.cpp` implements the same binary C ABI using the system WebAuthn DLL.
It requires WebAuthn API version 6 or later, checks every loaded function, uses
make-credential options v6 and get-assertion options v6, requires UV and resident
credentials, requests PRF support, and maps inputs to each allowed credential.
Windows performs the WebAuthn PRF salt normalization; raw CTAP salt mode is off.

Build with CMake and a Windows C++ toolchain:

```powershell
cmake -S native/windows -B build/windows
cmake --build build/windows --config Release
```

The build downloads content-hash-pinned Microsoft WebAuthn and nlohmann JSON
headers. Both projects use the MIT license; ship [their notices](THIRD_PARTY_NOTICES.md)
with the adapter.
Place `keypass.dll` beside the consuming Dart executable and ship the compiler's
runtime dependencies. Dart discovers it automatically. The WebAuthn DLL is
loaded from System32 only. Configure `Keypass.system(rpId: ...)` explicitly.
Windows has no Apple/Android-style app-domain association in this adapter.

The foreground HWND must belong to the calling app. Headless processes and
windows owned by another app return `hostUnavailable`; no hidden window is
created. The OS call runs off the Dart thread with native cancellation IDs and
a deadline. Secret output is copied into the binary response, and owned/native
buffers are erased before release. The DLL remains loaded for process lifetime
so a late OS completion cannot execute unloaded code.

The x64 DLL has cross-compiled against the pinned official header with compiler
warnings treated as errors. Windows runtime, MSVC packaging, Windows Hello,
third-party providers and hardware keys have **not** been tested. A successful
Windows Hello sign-in without PRF is `prfUnavailable`, never a substitute secret.

On macOS/Linux with Docker, `sh tool/windows_cross_check.sh` builds the x64 DLL
and exports it to `build/native/keypass.dll`. This checks compilation only.
