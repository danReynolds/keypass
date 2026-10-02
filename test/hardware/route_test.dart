import 'package:keypass/keypass_backend.dart';
import 'package:test/test.dart';
import '../support/recording_backend.dart';

PasskeyRecord record(PasskeyRoute route, {String? rpId}) {
  final original = binding(domain: rpId ?? 'vault.example.com');
  return recordFromBinding(
    route == PasskeyRoute.system
        ? original
        : PasskeyBinding(
            route: route,
            domain: original.domain,
            credentialId: original.credentialId,
            userId: original.userId,
            publicKeyCose: original.publicKeyCose,
            input: original.input,
            authenticatorState: AuthenticatorState(
              backupEligible: false,
              backupState: false,
              signCount: 0,
            ),
          ),
  );
}

void main() {
  Matcher error(PasskeyErrorCode code) =>
      throwsA(isA<PasskeyException>().having((e) => e.code, 'code', code));

  for (final route in PasskeyRoute.values) {
    test(
      '$route client rejects the other route before backend creation',
      () async {
        var factories = 0;
        final backend = RecordingBackend();
        final client = keypassWithBackendFactory(
          createBackend: () {
            factories++;
            return backend;
          },
          rpId: 'vault.example.com',
          route: route,
        );
        final other = route == PasskeyRoute.system
            ? PasskeyRoute.hardware
            : PasskeyRoute.system;

        await expectLater(
          client.unlock(record(other)),
          error(PasskeyErrorCode.invalidBinding),
        );

        expect(
          factories,
          0,
          reason: 'A mismatch must not open native resources.',
        );
        expect(backend.availabilityCalls, 0);
        expect(backend.registrations, isEmpty);
        expect(backend.evaluations, isEmpty);
        expect(backend.disposed, 0);
      },
    );

    test(
      '$route client rejects a different RP before backend creation',
      () async {
        var factories = 0;
        final client = keypassWithBackendFactory(
          createBackend: () {
            factories++;
            return RecordingBackend();
          },
          rpId: 'vault.example.com',
          route: route,
        );

        await expectLater(
          client.unlock(record(route, rpId: 'other.example.com')),
          error(PasskeyErrorCode.invalidBinding),
        );

        expect(factories, 0);
      },
    );
  }
}
