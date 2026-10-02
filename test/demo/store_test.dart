import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:keypass/keypass_backend.dart';
import 'package:test/test.dart';

// Share the Flutter-free demo format without depending on its Flutter app.
// ignore: avoid_relative_lib_imports
import '../../demo/provider_app/lib/store.dart' as demo;
import '../support/recording_backend.dart';

Matcher fails(PasskeyErrorCode code) =>
    throwsA(isA<PasskeyException>().having((e) => e.code, 'code', code));

void main() {
  late Directory directory;
  late demo.DemoStore store;
  late RecordingBackend backend;
  late Keypass client;

  Keypass open(RecordingBackend backend) => keypassWithBackendFactory(
    createBackend: () => backend,
    rpId: 'vault.example.com',
  );

  setUp(() async {
    directory = await Directory.systemTemp.createTemp('keypass-demo-test-');
    store = demo.DemoStore(File('${directory.path}/state/marker.json'));
    backend = RecordingBackend();
    client = open(backend);
  });
  tearDown(() async {
    await directory.delete(recursive: true);
  });

  Future<void> enroll() =>
      store.enroll(client, cancellation: PasskeyCancellation());
  Future<void> unlock() =>
      store.unlock(client, cancellation: PasskeyCancellation());

  test(
    'a new SDK instance recovers the saved marker and commits updated state',
    () async {
      await enroll();
      final original =
          jsonDecode(await store.file.readAsString()) as Map<String, dynamic>;
      expect(original['version'], 1);
      expect(backend.evaluations, hasLength(2));

      backend = RecordingBackend();
      backend.onEvaluate = (request, _) async => backend.assertion(
        request.bindings.single.withState(
          AuthenticatorState(
            backupEligible: true,
            backupState: true,
            signCount: 1,
          ),
        ),
      );
      client = open(backend);
      store = demo.DemoStore(File(store.file.path));
      await unlock();
      final updated =
          jsonDecode(await store.file.readAsString()) as Map<String, dynamic>;
      expect((updated['binding'] as Map)['signCount'], 1);
      expect(backend.registrations, isEmpty);
      expect(backend.evaluations, hasLength(1));
      expect(updated['encryptedMarker'], isNot(original['encryptedMarker']));
      expect(File('${store.file.path}.pending').existsSync(), isFalse);
      for (final buffer in backend.buffers) {
        expect(buffer, everyElement(0));
      }
    },
  );

  test('enrollment never overwrites an existing marker', () async {
    await enroll();
    final original = await store.file.readAsString();
    final calls = backend.availabilityCalls;
    await expectLater(enroll(), fails(PasskeyErrorCode.invalidRequest));
    expect(await store.file.readAsString(), original);
    expect(backend.availabilityCalls, calls);
    expect(backend.registrations, hasLength(1));
  });

  test('malformed marker is rejected before any provider request', () async {
    await enroll();
    final saved =
        jsonDecode(await store.file.readAsString()) as Map<String, dynamic>;
    (saved['encryptedMarker'] as Map)['nonce'] = 'AA';
    await store.file.writeAsString(jsonEncode(saved));
    final calls = backend.availabilityCalls;
    await expectLater(unlock(), fails(PasskeyErrorCode.invalidBinding));
    expect(backend.availabilityCalls, calls);
    expect(backend.evaluations, hasLength(2));
  });

  test(
    'wrong PRF preserves the previous file and clears returned bytes',
    () async {
      await enroll();
      final original = await store.file.readAsString();
      backend.onEvaluate = (request, _) async =>
          backend.assertion(request.bindings.single, byte: 8);
      await expectLater(unlock(), throwsA(isA<SecretBoxAuthenticationError>()));
      expect(await store.file.readAsString(), original);
      expect(backend.buffers.last, everyElement(0));
    },
  );

  test('binding metadata tampering fails authenticated decryption', () async {
    await enroll();
    final saved =
        jsonDecode(await store.file.readAsString()) as Map<String, dynamic>;
    (saved['binding'] as Map)['signCount'] = 1;
    final tampered = jsonEncode(saved);
    await store.file.writeAsString(tampered);
    await expectLater(unlock(), throwsA(isA<SecretBoxAuthenticationError>()));
    expect(await store.file.readAsString(), tampered);
  });

  for (final code in [
    PasskeyErrorCode.cancelled,
    PasskeyErrorCode.prfUnavailable,
  ]) {
    test('failed enrollment leaves no saved marker: ${code.name}', () async {
      backend.onEvaluate = (request, _) async {
        if (backend.evaluations.length == 2) {
          throw PasskeyException(code);
        }
        return backend.assertion(request.bindings.single);
      };
      await expectLater(enroll(), fails(code));
      expect(store.exists, isFalse);
      expect(File('${store.file.path}.pending').existsSync(), isFalse);
      expect(backend.buffers.single, everyElement(0));
    });
  }

  test(
    'hardware import checks namespace and preserves ciphertext and source',
    () async {
      final provider = binding();
      final hardware = PasskeyBinding(
        domain: 'dev.keypass.import-test',
        route: PasskeyRoute.hardware,
        transports: ['usb', 'nfc'],
        authenticatorState: AuthenticatorState(
          backupEligible: false,
          backupState: false,
          signCount: 3,
        ),
        credentialId: provider.credentialId,
        userId: provider.userId,
        publicKeyCose: provider.publicKeyCose,
        input: provider.input,
      );
      final key = SecretKeyData(List.filled(32, 9));
      late Map<String, Object?> encrypted;
      try {
        encrypted = await demo.encryptMarker(key, recordFromBinding(hardware));
      } finally {
        key.destroy();
      }
      final original = jsonEncode({
        'version': 1,
        'binding': hardware.toJson(),
        'encryptedMarker': encrypted,
      });
      final source = File('${directory.path}/import.json');
      await source.writeAsString(original);
      await expectLater(
        store.importHardware(source, namespace: 'dev.keypass.wrong'),
        fails(PasskeyErrorCode.invalidBinding),
      );
      expect(store.exists, false);
      await store.importHardware(source, namespace: hardware.domain);
      expect(jsonDecode(await store.file.readAsString()), jsonDecode(original));
      expect(await source.readAsString(), original);
      await expectLater(
        store.importHardware(source, namespace: hardware.domain),
        fails(PasskeyErrorCode.invalidRequest),
      );
      expect(jsonDecode(await store.file.readAsString()), jsonDecode(original));
    },
  );

  test('hardware import rejects a provider binding', () async {
    await enroll();
    final imported = demo.DemoStore(File('${directory.path}/other.json'));
    await expectLater(
      imported.importHardware(store.file, namespace: 'vault.example.com'),
      fails(PasskeyErrorCode.invalidBinding),
    );
    expect(imported.exists, false);
  });
}
