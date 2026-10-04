import 'dart:async';

import 'package:keypass/keypass_backend.dart';
import 'package:keypass/src/hardware/backend.dart';
import 'package:keypass/src/native/backend.dart';
import 'package:test/test.dart';

void main() {
  for (final hardware in [false, true]) {
    test(
      '${hardware ? 'hardware' : 'system'} readiness cancels and drains',
      () async {
        final transport = _PendingReadiness();
        final backend = hardware
            ? HardwarePasskeyBackend(transport, namespace: 'vault.example.com')
            : NativePasskeyBackend(transport, domain: 'vault.example.com');
        final client = keypassWithBackendFactory(
          rpId: 'vault.example.com',
          route: hardware ? PasskeyRoute.hardware : PasskeyRoute.system,
          createBackend: () => backend,
        );
        final cancellation = PasskeyCancellation();
        var settled = false;
        final creating = client.create(
          label: 'Test',
          cancellation: cancellation,
        );
        final outcome = expectLater(
          creating.whenComplete(() => settled = true),
          throwsA(
            isA<PasskeyException>().having(
              (e) => e.code,
              'code',
              PasskeyErrorCode.cancelled,
            ),
          ),
        );
        await transport.entered.future;
        cancellation.cancel();
        await transport.cancelled.future.timeout(const Duration(seconds: 2));
        expect(settled, isFalse);
        expect(transport.disposed, isFalse);
        transport.release.complete();
        await outcome;
        expect(transport.disposed, isTrue);
        expect(transport.operations, [hardware ? 'discover' : 'availability']);
        // The shared operation gate is released only after native cleanup.
        final next = await keypassWithBackendFactory(
          rpId: 'vault.example.com',
          createBackend: () => const UnavailablePasskeyBackend(),
        ).check();
        expect(next.reason, isNot(PasskeyErrorCode.busy));
      },
    );
  }
}

final class _PendingReadiness implements NativeTransport {
  final entered = Completer<void>();
  final cancelled = Completer<void>();
  final release = Completer<void>();
  final operations = <String>[];
  bool disposed = false;
  @override
  Future<NativeReply> exchange(
    Map<String, Object?> request,
    PasskeyCancellation cancellation,
  ) async {
    operations.add(request['operation']! as String);
    final listener = cancellation.onCancel.listen((_) {
      if (!cancelled.isCompleted) cancelled.complete();
    });
    try {
      entered.complete();
      await release.future;
      throw const PasskeyException(PasskeyErrorCode.cancelled);
    } finally {
      await listener.cancel();
    }
  }

  @override
  Future<void> dispose() async => disposed = true;
}
