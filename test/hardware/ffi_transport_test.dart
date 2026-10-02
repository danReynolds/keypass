import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:keypass/keypass_backend.dart';
import 'package:keypass/src/hardware/ffi_transport.dart';
import 'package:test/test.dart';

void main() {
  if (Platform.isWindows) return;
  late Directory directory;
  late DynamicLibrary library;
  late int Function() submitted;
  late int Function() freed;
  setUpAll(() async {
    directory = await Directory.systemTemp.createTemp('keypass-hardware-ffi-');
    final path =
        '${directory.path}/fixture.${Platform.isMacOS ? 'dylib' : 'so'}';
    final built = await Process.run('cc', [
      '-shared',
      '-fPIC',
      'test/hardware/ffi_fixture.c',
      '-o',
      path,
    ]);
    expect(built.exitCode, 0, reason: built.stderr.toString());
    library = DynamicLibrary.open(path);
    submitted = library.lookupFunction<Int32 Function(), int Function()>(
      'fixture_submitted',
    );
    freed = library.lookupFunction<Int32 Function(), int Function()>(
      'fixture_freed',
    );
  });
  tearDownAll(() => directory.delete(recursive: true));
  Matcher code(PasskeyErrorCode code) =>
      throwsA(isA<PasskeyException>().having((e) => e.code, 'code', code));
  test(
    'NFC presence event precedes the PIN without releasing a secret',
    () async {
      final events = <String>[];
      final transport = HardwareFfiTransport(
        HardwareInteraction(
          onEvent: (status) => events.add(status.name),
          requestPin: (_, _) async {
            events.add('pin');
            return Uint8List.fromList([49, 50, 51, 52]);
          },
        ),
        library: library,
      );
      final reply = await transport.exchange({
        'case': 'nfc',
      }, PasskeyCancellation());
      expect(events, ['presentKey', 'pin']);
      expect(reply.secret, everyElement(7));
      reply.clear();
      await transport.dispose();
    },
  );
  test(
    'PIN uses binary ABI and is cleared; secret has independent ownership',
    () async {
      final pin = Uint8List.fromList([49, 50, 51, 52]);
      final before = freed();
      final transport = HardwareFfiTransport(
        HardwareInteraction(
          requestPin: (request, cancellation) async {
            expect(request.attemptsRemaining, 8);
            return pin;
          },
        ),
        library: library,
      );
      final reply = await transport.exchange({
        'case': 'success',
      }, PasskeyCancellation());
      expect(submitted(), 1);
      expect(pin, everyElement(0));
      expect(freed(), before + 2);
      expect(reply.secret, everyElement(7));
      reply.clear();
      expect(reply.secret, everyElement(0));
      await transport.dispose();
    },
  );
  test(
    'cancellation drains a late native secret and clears late PIN callback',
    () async {
      final callback = Completer<Uint8List?>();
      final entered = Completer<void>();
      final cancellation = PasskeyCancellation();
      final transport = HardwareFfiTransport(
        HardwareInteraction(
          requestPin: (_, signal) {
            entered.complete();
            return callback.future;
          },
        ),
        library: library,
      );
      final pending = transport.exchange({'case': 'late'}, cancellation);
      final done = expectLater(pending, code(PasskeyErrorCode.cancelled));
      await entered.future;
      cancellation.cancel();
      await done;
      final pin = Uint8List.fromList([49, 50, 51, 52]);
      callback.complete(pin);
      await Future<void>.delayed(Duration.zero);
      expect(submitted(), 0);
      expect(pin, everyElement(0));
      await transport.dispose();
    },
  );
  test(
    'missing PIN UI fails with pinRequired and native slot is reusable',
    () async {
      final transport = HardwareFfiTransport(
        const HardwareInteraction(),
        library: library,
      );
      await expectLater(
        transport.exchange({}, PasskeyCancellation()),
        code(PasskeyErrorCode.pinRequired),
      );
      await expectLater(
        transport.exchange({}, PasskeyCancellation()),
        code(PasskeyErrorCode.pinRequired),
      );
      await transport.dispose();
    },
  );
  test('read-only PIN is rejected before native submission', () async {
    final transport = HardwareFfiTransport(
      HardwareInteraction(
        requestPin: (_, _) async =>
            Uint8List.fromList([49, 50, 51, 52]).asUnmodifiableView(),
      ),
      library: library,
    );
    await expectLater(
      transport.exchange({}, PasskeyCancellation()),
      code(PasskeyErrorCode.invalidRequest),
    );
    expect(submitted(), 0);
    await transport.dispose();
  });
  test('malformed interaction drains before the next request', () async {
    final transport = HardwareFfiTransport(
      const HardwareInteraction(),
      library: library,
    );
    await expectLater(
      transport.exchange({'case': 'malformed'}, PasskeyCancellation()),
      throwsFormatException,
    );
    await expectLater(
      transport.exchange({}, PasskeyCancellation()),
      code(PasskeyErrorCode.pinRequired),
    );
    await transport.dispose();
  });
}
