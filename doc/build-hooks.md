# Desktop native build hooks

Keypass owns `hook/build.dart`. A consumer depending on Keypass, directly or
transitively, gets its desktop USB adapter through Dart's code-assets mechanism.
There is no Flutter dependency and no change to `Keypass.hardware`.

From the application's package/workspace, run `dart run`, `dart test`, or
`dart build cli`. The SDK invokes and caches the hook, and the internal `@Native`
bindings resolve `package:keypass/src/hardware/bindings.dart`. Consumers do not
set a library path or copy files beside their Dart SDK. `dart pub get` resolves
dependencies; it does not compile them.

## Build hosts

The source-build hook requires a C++17 compiler, CMake >= 3.22, pkg-config,
Python 3, libfido2 >= 1.16, OpenSSL 3, and libcbor development files. Linux also
needs patchelf and binutils. Maintainers/CI can prepare them with
`bash tool/install_hardware_build_deps.sh`; this explicit setup script may use
Homebrew or sudo/apt. The hook itself never installs system packages or uses sudo.
The JSON header is downloaded at its fixed version with SHA-256 verification.

The first build can take longer. Subsequent invocations reuse cached outputs.
Source files, packaging code, pubspec, and the resolved dependency libraries are
registered as inputs. Builds write under the SDK-provided output directory,
not the package source tree. System development-library changes invalidate the
recorded dependencies. Use a fresh build cache after changing compiler/toolchain
configuration; this first implementation does not model every system header.

Desktop builds currently require a matching macOS/Linux host and architecture.
Cross targets fail with an explicit diagnostic instead of shipping host libraries.
iOS, Android, and Windows emit no desktop hardware assets and retain their
existing native host linking, permissions and lifecycle setup. This milestone
qualifies Dart CLI builds; Flutter desktop framework packaging needs its own
qualification. Hooks do not grant AASA, app associations or USB permissions.

## Bundling and security boundary

The build reuses the desktop CMake implementation. The adapter, libfido2,
libcrypto and libcbor are declared as four dynamic code assets. Their library
references are relocated to their bundled siblings; macOS system libraries and
Linux's documented OS baseline remain system dependencies. Unexpected native
dependencies fail the build. Native dependency notices accompany the source
package; application distributors must retain the notices in their distribution.

The ABI still passes PINs and PRF bytes through binary buffers and clears them.
A missing/invalid asset is an availability error, never a reason to choose
another provider or search the current directory for a replacement library.

For a distributable Dart CLI use `dart build cli`, retaining its whole `bundle`
directory (`bin` and `lib`). `dart compile` does not orchestrate native assets.
Custom AOT/embedded packagers may explicitly set
`-Dkeypass.hardware.manual_bundle=true` and ship the reviewed sibling-library
layout beside the runtime, or link the platform adapter into the host process.
That compatibility path does not run hooks or prepare any libraries itself.
Production signing, notarization and installed-upgrade qualification remain
responsibilities of the application packager.

Dart 3.12 prepares hooks relative to the invoking project. An absolute source
entrypoint launched from an unrelated directory may skip hook execution and
reuse an old native-assets file. Local command routers must arrange hook
preparation in the owning project while preserving the application's caller
working directory. Do not treat a previously warmed cache as a clean-launch test.

## Validation

`dart test test/hooks` loads the real adapter and exercises a rejected worker
request twice (no device enumeration or credential ceremony). It also checks
that mobile/Windows targets skip the desktop adapter and foreign desktop targets
are rejected. `python3 tool/test_build_hooks.py` creates an independent app with
a transitive Keypass dependency, exercises source execution/caching, builds its
CLI, relocates the entire bundle and verifies both direct and symlink launch.
The existing binary-buffer/cleanup tests still inject their native fixture.

These checks prove asset loading and packaging, not physical key enrollment.
