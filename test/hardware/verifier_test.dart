import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:keypass/keypass_backend.dart';
import 'package:keypass/src/hardware/backend.dart';
import 'package:keypass/src/webauthn/verifier.dart';
import 'package:test/test.dart';

void main() {
  late Map<String, dynamic> vectors;
  late WebAuthnVerifier verifier;
  late PasskeyBinding binding;
  Uint8List b(Object? value) =>
      base64Url.decode(base64Url.normalize(value as String));
  final rejected = throwsA(
    isA<PasskeyException>().having(
      (e) => e.code,
      'code',
      PasskeyErrorCode.verificationFailed,
    ),
  );
  setUpAll(() async {
    final result = await Process.run('node', ['test/hardware/vectors.mjs']);
    expect(result.exitCode, 0, reason: result.stderr.toString());
    vectors = jsonDecode(result.stdout as String) as Map<String, dynamic>;
    verifier = WebAuthnVerifier.hardware(
      domain: vectors['namespace'] as String,
    );
    final registered = verifier.hardwareRegistration(
      credentialId: b(vectors['id']),
      authenticatorData: b(vectors['registration']),
    );
    binding = PasskeyBinding(
      route: PasskeyRoute.hardware,
      transports: const ['usb', 'nfc'],
      domain: vectors['namespace'] as String,
      credentialId: registered.credentialId,
      userId: b(vectors['user']),
      publicKeyCose: registered.publicKeyCose,
      input: b(vectors['input']),
      authenticatorState: registered.state,
    );
  });
  AuthenticatorState verify(String name, {PasskeyBinding? previous}) {
    final assertion = vectors[name] as Map<String, dynamic>;
    return verifier.hardwareAssertion(
      clientDataHash: b(vectors['clientHash']),
      credentialId: b(vectors['id']),
      binding: previous ?? binding,
      userHandle: b(vectors['user']),
      authenticatorData: b(assertion['authenticatorData']),
      signature: b(assertion['signature']),
    );
  }

  test('independently signed direct CTAP assertion and salt normalization', () {
    expect(verify('assertion').signCount, 1);
    expect(hardwarePrfSalt(b(vectors['input'])), b(vectors['salt']));
    expect(
      hardwareClientHash(
        binding.domain,
        b(vectors['challenge']),
        registration: false,
      ),
      b(vectors['clientHash']),
    );
    expect(
      hardwareClientHash(
        binding.domain,
        b(vectors['challenge']),
        registration: true,
      ),
      isNot(b(vectors['clientHash'])),
    );
  });
  for (final name in [
    'missingUV',
    'missingUP',
    'wrongRP',
    'wrongHash',
    'backedUp',
    'missingExtension',
    'shortExtension',
  ]) {
    test('rejects signed $name', () => expect(() => verify(name), rejected));
  }
  for (final name in ['missingPrf', 'missingProtection', 'weakProtection']) {
    test(
      'rejects enrollment $name',
      () => expect(
        () => verifier.hardwareRegistration(
          credentialId: b(vectors['id']),
          authenticatorData: b(vectors[name]),
        ),
        rejected,
      ),
    );
  }
  test('replay and counter rollback are rejected', () {
    final updated = binding.withState(verify('assertion'));
    expect(() => verify('assertion', previous: updated), rejected);
    expect(() => verify('counterZero', previous: updated), rejected);
  });
  test('truncated registration and substituted credential/key fail', () {
    final data = b(vectors['registration']);
    for (var n = 0; n < data.length; n++) {
      expect(
        () => verifier.hardwareRegistration(
          credentialId: binding.credentialId,
          authenticatorData: Uint8List.sublistView(data, 0, n),
        ),
        rejected,
      );
    }
    final assertion = vectors['assertion'] as Map<String, dynamic>;
    expect(
      () => verifier.hardwareAssertion(
        clientDataHash: b(vectors['clientHash']),
        credentialId: Uint8List(32),
        binding: binding,
        userHandle: binding.userId,
        authenticatorData: b(assertion['authenticatorData']),
        signature: b(assertion['signature']),
      ),
      rejected,
    );
    final damaged = b(assertion['signature']);
    damaged[damaged.length - 1] ^= 1;
    expect(
      () => verifier.hardwareAssertion(
        clientDataHash: b(vectors['clientHash']),
        credentialId: binding.credentialId,
        binding: binding,
        userHandle: binding.userId,
        authenticatorData: b(assertion['authenticatorData']),
        signature: damaged,
      ),
      rejected,
    );
  });
  test(
    'hardware binding preserves route, UV policy, salt and transport hints',
    () {
      final encoded = binding.toJson();
      expect(encoded['version'], 3);
      expect(encoded['verification'], 'required');
      expect(PasskeyBinding.fromJson(encoded).toJson(), encoded);
      final updated = binding.withState(verify('assertion'));
      expect(updated.route, PasskeyRoute.hardware);
      expect(updated.transports, ['usb', 'nfc']);
      for (final change in [
        {'route': 'provider'},
        {'verification': 'preferred'},
        {
          'transports': ['ble'],
        },
        {
          'transports': ['usb', 'usb'],
        },
        {'version': 2},
        {'prf': 'raw-hmac-secret'},
      ]) {
        expect(
          () => PasskeyBinding.fromJson({...encoded, ...change}),
          throwsA(isA<PasskeyException>()),
        );
      }
    },
  );
  test('web profile cannot be used for direct hardware evidence', () {
    final web = WebAuthnVerifier(
      domain: binding.domain,
      origin: 'https://${binding.domain}',
    );
    expect(
      () => web.hardwareRegistration(
        credentialId: binding.credentialId,
        authenticatorData: b(vectors['registration']),
      ),
      rejected,
    );
  });
}
