import 'package:keypass/keypass_backend.dart';
import 'package:test/test.dart';

// Exercise the Flutter-free demo helper without adding Flutter to this package.
// ignore: avoid_relative_lib_imports
import '../../demo/provider_app/lib/provider_progress.dart';
import '../support/recording_backend.dart';

void main() {
  test(
    'progress observes exactly creation and two assertions, then stops',
    () async {
      final native = RecordingBackend();
      final events = <String>[];
      final client = keypassWithBackendFactory(
        createBackend: () => ProgressBackend(native, (call, phase) async {
          events.add('${call.name}:${phase.name}');
        }),
        rpId: 'vault.example.com',
      );
      final result = await client.create(label: 'Test');
      try {
        expect(result.secret, everyElement(7));
      } finally {
        result.dispose();
      }
      expect(native.registrations, hasLength(1));
      expect(native.evaluations, hasLength(2));
      expect(events, [
        'register:started',
        'register:succeeded',
        'evaluate:started',
        'evaluate:succeeded',
        'evaluate:started',
        'evaluate:succeeded',
      ]);
      for (final buffer in native.buffers) {
        expect(buffer, everyElement(0));
      }
      expect(native.disposed, 1);
    },
  );

  test('cancelled assertion is reported once and never retried', () async {
    final native = RecordingBackend();
    final events = <String>[];
    native.onEvaluate = (_, _) async {
      throw const PasskeyException(PasskeyErrorCode.cancelled);
    };
    final client = keypassWithBackendFactory(
      createBackend: () => ProgressBackend(native, (call, phase) async {
        events.add('${call.name}:${phase.name}');
      }),
      rpId: 'vault.example.com',
    );
    await expectLater(
      client.create(label: 'Test'),
      throwsA(
        isA<PasskeyException>().having(
          (e) => e.code,
          'code',
          PasskeyErrorCode.cancelled,
        ),
      ),
    );
    expect(native.registrations, hasLength(1));
    expect(native.evaluations, hasLength(1));
    expect(events, [
      'register:started',
      'register:succeeded',
      'evaluate:started',
      'evaluate:failed',
    ]);
  });

  test(
    'diagnostic failure does not retry or discard provider results',
    () async {
      final native = RecordingBackend();
      final client = keypassWithBackendFactory(
        createBackend: () => ProgressBackend(
          native,
          (_, _) async => throw StateError('receipt'),
        ),
        rpId: 'vault.example.com',
      );
      final result = await client.create(label: 'Test');
      try {
        expect(result.secret, everyElement(7));
        expect(result.record.rpId, 'vault.example.com');
      } finally {
        result.dispose();
      }
      expect(native.registrations, hasLength(1));
      expect(native.evaluations, hasLength(2));
      for (final buffer in native.buffers) {
        expect(buffer, everyElement(0));
      }
    },
  );
}
