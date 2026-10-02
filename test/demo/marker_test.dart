import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:keypass/keypass_backend.dart';
import 'package:test/test.dart';
// Share the Flutter-free demo format without depending on its Flutter app.
// ignore: avoid_relative_lib_imports
import '../../demo/provider_app/lib/store.dart' as demo;
import '../support/recording_backend.dart';

void main() {
  for (final hardware in [false, true]) {
    test('legacy v${hardware ? 3 : 2} record retains marker AAD', () async {
      // Literal legacy field order: ciphertext created before the SDK rename
      // must still decrypt after deserializing into an opaque PasskeyRecord.
      final legacy = <String, Object>{
        'version': hardware ? 3 : 2,
        if (hardware) ...{
          'route': 'hardware',
          'verification': 'required',
          'transports': ['usb', 'nfc'],
        },
        'prf': 'webauthn-prf-v1',
        'domain': hardware ? 'dev.keypass.hardware-demo' : 'vault.example.com',
        'credentialId': 'AQ',
        'userId': 'Ag',
        'publicKeyCose': 'oA',
        'input': 'Aw',
        'backupEligible': !hardware,
        'backupState': !hardware,
        'signCount': 3,
      };
      final key = SecretKeyData(List.filled(32, 9));
      try {
        final legacyBox = await AesGcm.with256bits().encrypt(
          demo.marker,
          secretKey: key,
          nonce: List.filled(12, 4),
          aad: utf8.encode(jsonEncode(legacy)),
        );
        final record = PasskeyRecord.fromJson(legacy);
        expect(jsonEncode(record.toJson()), jsonEncode(legacy));
        await demo.decryptMarker(key, record, {
          'nonce': demo.encode(legacyBox.nonce),
          'ciphertext': demo.encode(legacyBox.cipherText),
          'tag': demo.encode(legacyBox.mac.bytes),
        });
      } finally {
        key.destroy();
      }
    });
  }

  test(
    'demo marker survives key recreation and authenticated state updates',
    () async {
      final original = binding();
      final first = await demo.derive(Uint8List(32)..fillRange(0, 32, 9));
      final saved = await demo.encryptMarker(
        first,
        recordFromBinding(original),
      );
      first.destroy();
      final reopened = await demo.derive(Uint8List(32)..fillRange(0, 32, 9));
      try {
        await demo.decryptMarker(reopened, recordFromBinding(original), saved);
        final updated = original.withState(
          AuthenticatorState(
            backupEligible: true,
            backupState: true,
            signCount: 1,
          ),
        );
        await expectLater(
          demo.decryptMarker(reopened, recordFromBinding(updated), saved),
          throwsA(anything),
        );
        final next = await demo.encryptMarker(
          reopened,
          recordFromBinding(updated),
        );
        await demo.decryptMarker(reopened, recordFromBinding(updated), next);
        expect(saved.keys, unorderedEquals(['nonce', 'ciphertext', 'tag']));
      } finally {
        reopened.destroy();
      }
    },
  );
  test('a different PRF cannot decrypt the demo marker', () async {
    final key = await demo.derive(Uint8List(32)..fillRange(0, 32, 1));
    final wrong = await demo.derive(Uint8List(32)..fillRange(0, 32, 2));
    try {
      final saved = await demo.encryptMarker(key, recordFromBinding(binding()));
      await expectLater(
        demo.decryptMarker(wrong, recordFromBinding(binding()), saved),
        throwsA(anything),
      );
    } finally {
      key.destroy();
      wrong.destroy();
    }
  });
}
