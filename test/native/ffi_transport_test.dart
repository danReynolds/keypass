import 'dart:ffi';
import 'dart:io';
import 'package:keypass/keypass.dart';
import 'package:keypass/src/native/ffi_transport.dart';
import 'package:test/test.dart';

void main() {
  if (Platform.isWindows) {
    return; // The portable fixture uses the system C compiler.
  }
  late Directory directory;
  late DynamicLibrary library;
  late int Function() frees;
  late int Function() wiped;
  setUpAll(() async {
    directory = await Directory.systemTemp.createTemp('keypass-ffi-test-');
    final path =
        '${directory.path}/fixture.${Platform.isMacOS ? 'dylib' : 'so'}';
    final result = await Process.run('cc', [
      '-shared',
      '-fPIC',
      'test/native/ffi_fixture.c',
      '-o',
      path,
    ]);
    expect(result.exitCode, 0, reason: result.stderr.toString());
    library = DynamicLibrary.open(path);
    frees = library.lookupFunction<Int32 Function(), int Function()>(
      'fixture_frees',
    );
    wiped = library.lookupFunction<Int32 Function(), int Function()>(
      'fixture_wiped',
    );
  });
  tearDownAll(() async => directory.delete(recursive: true));
  test(
    'binary secret transfers after native buffer is wiped and freed',
    () async {
      final transport = FfiNativeTransport(library: library);
      final before = frees();
      final reply = await transport.exchange({
        'case': 'success',
      }, PasskeyCancellation());
      expect(frees(), before + 1);
      expect(wiped(), 1);
      expect(reply.secret, everyElement(7));
      expect(reply.metadata, {'ok': true});
      reply.clear();
      expect(reply.secret, everyElement(0));
      await transport.dispose();
    },
  );
  test(
    'malformed public metadata still wipes and frees native secret',
    () async {
      final transport = FfiNativeTransport(library: library);
      final before = frees();
      await expectLater(
        transport.exchange({'case': 'malformed'}, PasskeyCancellation()),
        throwsFormatException,
      );
      expect(frees(), before + 1);
      expect(wiped(), 1);
      await transport.dispose();
    },
  );
  test(
    'cancel wins over late success and drains the returned secret',
    () async {
      final transport = FfiNativeTransport(library: library);
      final before = frees();
      final cancellation = PasskeyCancellation();
      final request = transport.exchange({'case': 'pending'}, cancellation);
      cancellation.cancel();
      await expectLater(
        request,
        throwsA(
          isA<PasskeyException>().having(
            (e) => e.code,
            'code',
            PasskeyErrorCode.cancelled,
          ),
        ),
      );
      expect(frees(), before + 1);
      expect(wiped(), 1);
      await transport.dispose();
    },
  );
}
