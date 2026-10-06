import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:keypass/keypass_backend.dart';
import 'package:keypass/src/hardware/bindings.dart';
import 'package:keypass/src/hardware/ffi_transport.dart';
import 'package:test/test.dart';

import '../../hook/build.dart' as hook;

void main() {
  for (final target in [OS.iOS, OS.android, OS.windows]) {
    test('$target does not build the desktop USB adapter', () async {
      await testCodeBuildHook(
        mainMethod: hook.main,
        targetOS: target,
        check: (_, output) => expect(output.assets.code, isEmpty),
      );
    });
  }
  test(
    'rejects foreign desktop libraries before invoking a compiler',
    () async {
      await expectLater(
        testCodeBuildHook(
          mainMethod: hook.main,
          targetOS: OS.current == OS.macOS ? OS.linux : OS.macOS,
          check: (_, _) {},
        ),
        throwsA(isA<UnsupportedError>()),
      );
    },
  );
  if (!Platform.isMacOS && !Platform.isLinux) return;
  test(
    'registered asset loads real ABI and drains a rejected worker request',
    () async {
      expect(hardwareAbiVersion(), 1);
      final transport = HardwareFfiTransport(const HardwareInteraction());
      try {
        for (var attempt = 0; attempt < 2; attempt++) {
          // Rejected before device enumeration, PIN entry or credential access.
          await expectLater(
            transport.exchange({
              'operation': 'abi_probe',
            }, PasskeyCancellation()),
            throwsA(
              isA<PasskeyException>().having(
                (error) => error.code,
                'code',
                PasskeyErrorCode.invalidRequest,
              ),
            ),
          );
        }
      } finally {
        await transport.dispose();
      }
    },
  );
}
