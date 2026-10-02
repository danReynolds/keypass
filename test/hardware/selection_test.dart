import 'dart:async';
import 'dart:typed_data';
import 'package:keypass/keypass_backend.dart';
import 'package:keypass/src/hardware/backend.dart';
import 'package:keypass/src/native/backend.dart';
import 'package:test/test.dart';

/// Discovery/selection fixture only; it never supplies an assertion or secret.
final class Devices implements NativeTransport {
  Devices({this.allowAttempt = false, this.single = false});

  final bool allowAttempt;
  final bool single;
  final operations = <String>[];
  final attemptedDevices = <String>[];
  int disposed = 0;

  @override
  Future<NativeReply> exchange(
    Map<String, Object?> request,
    PasskeyCancellation cancellation,
  ) async {
    operations.add(request['operation']! as String);
    if (request['operation'] != 'discover') {
      if (!allowAttempt) throw StateError('A ceremony must not start');
      attemptedDevices.add(request['device']! as String);
      throw const PasskeyException(PasskeyErrorCode.credentialUnavailable);
    }
    return NativeReply({
      'devices': [
        {'id': 'a' * 64, 'name': 'First key', 'transport': 'usb'},
        if (!single) {'id': 'b' * 64, 'name': 'Second key', 'transport': 'nfc'},
      ],
    });
  }

  @override
  Future<void> dispose() async => disposed++;
}

void main() {
  Matcher error(PasskeyErrorCode code) =>
      throwsA(isA<PasskeyException>().having((e) => e.code, 'code', code));

  PasskeyRegistrationRequest request() => PasskeyRegistrationRequest(
    domain: 'dev.example.test',
    displayName: 'Example',
    label: 'Test',
    userId: Uint8List(32),
    challenge: Uint8List(32),
    input: Uint8List(32),
  );

  PasskeyRecord savedRecord() => recordFromBinding(
    PasskeyBinding(
      route: PasskeyRoute.hardware,
      domain: 'dev.example.test',
      credentialId: Uint8List.fromList([1]),
      userId: Uint8List(32),
      publicKeyCose: Uint8List.fromList([0xa0]),
      input: Uint8List(32),
      authenticatorState: AuthenticatorState(
        backupEligible: false,
        backupState: false,
        signCount: 0,
      ),
    ),
  );

  test(
    'multiple attached keys require explicit selection before a ceremony',
    () async {
      final transport = Devices();
      final backend = HardwarePasskeyBackend(
        transport,
        namespace: 'dev.example.test',
      );
      try {
        await expectLater(
          backend.register(request(), PasskeyCancellation()),
          error(PasskeyErrorCode.deviceSelectionRequired),
        );
        expect(transport.operations, ['discover']);
      } finally {
        await backend.dispose();
      }
    },
  );

  test(
    'cancellation settles without waiting for a hanging selection callback',
    () async {
      final transport = Devices();
      final selection = Completer<HardwareConnection?>();
      final entered = Completer<void>();
      late HardwareConnection offered;
      late PasskeyCancellation prompt;
      final cancellation = PasskeyCancellation();
      final backend = HardwarePasskeyBackend(
        transport,
        namespace: 'dev.example.test',
        interaction: HardwareInteraction(
          selectConnection: (connections, signal) {
            expect(connections.map((c) => c.name), ['First key', 'Second key']);
            expect(connections.map((c) => c.transport), [
              HardwareTransport.usb,
              HardwareTransport.nfc,
            ]);
            offered = connections.first;
            prompt = signal;
            entered.complete();
            return selection.future;
          },
        ),
      );
      try {
        final pending = backend.register(request(), cancellation);
        final stopped = expectLater(pending, error(PasskeyErrorCode.cancelled));
        await entered.future;
        cancellation.cancel();
        await stopped.timeout(const Duration(seconds: 1));
        expect(prompt.isCancelled, isTrue);

        selection.complete(offered);
        await Future<void>.delayed(Duration.zero);
        expect(transport.operations, ['discover']);
      } finally {
        await backend.dispose();
      }
    },
  );

  test(
    'a stale offered connection fails before any key receives a request',
    () async {
      final transports = <Devices>[];
      HardwareConnection? stale;
      var prompts = 0;
      final interaction = HardwareInteraction(
        selectConnection: (connections, _) async {
          prompts++;
          if (stale == null) {
            stale = connections.last;
            return null;
          }
          expect(stale!.name, connections.last.name);
          expect(stale!.transport, connections.last.transport);
          expect(identical(stale, connections.last), isFalse);
          return stale;
        },
      );
      final client = keypassWithBackendFactory(
        rpId: 'dev.example.test',
        route: PasskeyRoute.hardware,
        createBackend: () {
          final transport = Devices();
          transports.add(transport);
          return HardwarePasskeyBackend(
            transport,
            namespace: 'dev.example.test',
            interaction: interaction,
          );
        },
      );

      await expectLater(
        client.unlock(savedRecord()),
        error(PasskeyErrorCode.cancelled),
      );
      await expectLater(
        client.unlock(savedRecord()),
        error(PasskeyErrorCode.invalidRequest),
      );

      expect(prompts, 2);
      expect(transports, hasLength(2));
      for (final transport in transports) {
        expect(transport.operations, everyElement('discover'));
        expect(transport.attemptedDevices, isEmpty);
        expect(transport.disposed, 1);
      }
    },
  );

  test(
    'each facade operation offers a fresh choice after a failed ceremony',
    () async {
      final transports = <Devices>[];
      final offered = <List<HardwareConnection>>[];
      final interaction = HardwareInteraction(
        selectConnection: (connections, _) async {
          offered.add(connections);
          // A UI may reorder its local list and return the original option.
          final reordered = connections.reversed.toList();
          return offered.length == 1 ? reordered.first : reordered.last;
        },
      );
      final client = keypassWithBackendFactory(
        rpId: 'dev.example.test',
        route: PasskeyRoute.hardware,
        createBackend: () {
          final transport = Devices(allowAttempt: true);
          transports.add(transport);
          return HardwarePasskeyBackend(
            transport,
            namespace: 'dev.example.test',
            interaction: interaction,
          );
        },
      );

      for (var i = 0; i < 2; i++) {
        await expectLater(
          client.unlock(savedRecord()),
          error(PasskeyErrorCode.credentialUnavailable),
        );
      }

      expect(offered, hasLength(2));
      expect(identical(offered[0].first, offered[1].first), isFalse);
      expect(transports[0].attemptedDevices, ['b' * 64]);
      expect(transports[1].attemptedDevices, ['a' * 64]);
      expect(transports.map((t) => t.disposed), [1, 1]);
    },
  );

  test('a sole connection needs no picker', () async {
    final transport = Devices(allowAttempt: true, single: true);
    final backend = HardwarePasskeyBackend(
      transport,
      namespace: 'dev.example.test',
    );
    try {
      await expectLater(
        backend.register(request(), PasskeyCancellation()),
        error(PasskeyErrorCode.credentialUnavailable),
      );
      expect(transport.attemptedDevices, ['a' * 64]);
    } finally {
      await backend.dispose();
    }
  });
}
