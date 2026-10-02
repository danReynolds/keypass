import 'dart:ffi';
import 'dart:io';
import 'package:keypass/keypass.dart';
import 'package:keypass/src/native/backend.dart';
import 'package:keypass/src/native/ffi_transport.dart';
import 'package:test/test.dart';

void main() {
  test(
    'real Swift ABI fails closed in an unsigned Dart CLI without UI',
    () async {
      final transport = FfiNativeTransport(
        library: DynamicLibrary.open(
          File('build/native/libkeypass.dylib').absolute.path,
        ),
      );
      final backend = NativePasskeyBackend(
        transport,
        domain: 'vault.example.com',
      );
      final result = await backend.availability();
      expect(result.reason, PasskeyErrorCode.hostUnavailable);
      // Repeat proves the consumed response released the global operation slot.
      expect(
        (await backend.availability()).reason,
        PasskeyErrorCode.hostUnavailable,
      );
      await backend.dispose();
    },
    skip:
        !Platform.isMacOS ||
        !File('build/native/libkeypass.dylib').existsSync(),
  );
}
