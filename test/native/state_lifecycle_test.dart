import 'dart:typed_data';
import 'package:keypass/keypass_backend.dart';
import 'package:test/test.dart';
import '../support/recording_backend.dart';

void main() {
  test(
    'creation chains verification state; persisted records carry it into unlock',
    () async {
      final backends = <RecordingBackend>[];
      final client = keypassWithBackendFactory(
        rpId: 'vault.example.com',
        createBackend: () {
          final backend = RecordingBackend();
          backend.onEvaluate = (request, signal) async => PasskeyAssertion(
            credentialId: request.bindings.single.credentialId,
            secret: Uint8List(32),
            state: AuthenticatorState(
              backupEligible: true,
              backupState: true,
              signCount:
                  request.bindings.single.authenticatorState.signCount + 1,
            ),
          );
          backends.add(backend);
          return backend;
        },
      );

      late PasskeyRecord saved;
      final created = await client.create(label: 'Test');
      try {
        expect(backends, hasLength(1));
        expect(
          backends
              .single
              .evaluations[1]
              .bindings
              .single
              .authenticatorState
              .signCount,
          1,
        );
        expect(
          bindingFromRecord(created.record).authenticatorState.signCount,
          2,
        );
        expect(backends.single.disposed, 1);

        // Simulate the metadata actually persisted and decoded by a consumer.
        saved = PasskeyRecord.fromJson(created.record.toJson());
        expect(saved.id, created.record.id);
      } finally {
        created.dispose();
      }

      final unlocked = await client.unlock(saved);
      try {
        expect(backends, hasLength(2));
        expect(
          backends
              .last
              .evaluations
              .single
              .bindings
              .single
              .authenticatorState
              .signCount,
          2,
        );
        expect(
          bindingFromRecord(unlocked.record).authenticatorState.signCount,
          3,
        );
        expect(unlocked.record.id, saved.id);
        expect(backends.last.disposed, 1);
        expect(
          bindingFromRecord(saved).authenticatorState.signCount,
          2,
          reason:
              'Unlock returns updated metadata without mutating saved state.',
        );

        final restored = PasskeyRecord.fromJson(unlocked.record.toJson());
        expect(bindingFromRecord(restored).authenticatorState.signCount, 3);
        expect(restored.id, saved.id);
      } finally {
        unlocked.dispose();
      }

      expect(bindingFromRecord(created.record).authenticatorState.signCount, 2);
      expect(
        bindingFromRecord(unlocked.record).authenticatorState.signCount,
        3,
      );
      expect(backends.map((b) => b.disposed), [1, 1]);
    },
  );
}
