import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:keypass/keypass.dart';
import 'package:keypass/src/webauthn/bounded_cbor.dart';
import 'package:keypass/src/webauthn/client_data.dart';
import 'package:keypass/src/webauthn/verifier.dart';
import 'package:test/test.dart';

Uint8List bytes(Object? text) =>
    base64Url.decode(base64Url.normalize(text as String));
void main() {
  late Map<String, Object?> vectors;
  Map<String, Object?> section(String key) =>
      vectors[key] as Map<String, Object?>;
  Map<String, Object?> variant(String name) =>
      section('variants')[name] as Map<String, Object?>;
  late WebAuthnVerifier verifier;
  late VerifiedRegistration registered;
  setUpAll(() async {
    final result = await Process.run('node', ['test/webauthn/vectors.mjs']);
    expect(result.exitCode, 0, reason: result.stderr.toString());
    vectors = jsonDecode(result.stdout as String) as Map<String, Object?>;
    verifier = WebAuthnVerifier(
      domain: vectors['domain'] as String,
      origin: vectors['origin'] as String,
    );
    registered = verifier.registration(
      challenge: bytes(vectors['challenge']),
      credentialId: bytes(vectors['credentialId']),
      clientDataJSON: bytes(section('registration')['clientDataJSON']),
      attestationObject: bytes(section('registration')['attestationObject']),
      prfEnabled: true,
    );
  });
  AuthenticatorState verify(
    Map<String, Object?> response, {
    AuthenticatorState? previous,
    Uint8List? id,
    Uint8List? user,
    Uint8List? cose,
    Uint8List? signature,
  }) => verifier.assertion(
    challenge: bytes(vectors['challenge']),
    credentialId: id ?? bytes(vectors['credentialId']),
    expectedCredentialId: registered.credentialId,
    expectedUserId: bytes(vectors['userId']),
    userHandle: user ?? bytes(vectors['userId']),
    publicKeyCose: cose ?? registered.publicKeyCose,
    clientDataJSON: bytes(response['clientDataJSON']),
    authenticatorData: bytes(response['authenticatorData']),
    signature: signature ?? bytes(response['signature']),
    previousState: previous ?? registered.state,
  );
  final fails = throwsA(
    isA<PasskeyException>().having(
      (e) => e.code,
      'code',
      PasskeyErrorCode.verificationFailed,
    ),
  );
  test('Node ES256 registration and assertion verify in native Dart', () {
    expect(registered.credentialId, bytes(vectors['credentialId']));
    expect(registered.publicKeyCose, bytes(vectors['publicKeyCose']));
    expect(registered.state.backupEligible, isTrue);
    expect(verify(vectors['assertion'] as Map<String, Object?>).signCount, 0);
    expect(
      coseFromP256Spki(bytes(vectors['publicKeySpki'])),
      registered.publicKeyCose,
    );
  });
  for (final name in [
    'missingUV',
    'missingUP',
    'badBackup',
    'reserved',
    'changedBackupEligibility',
    'unexpectedAttestation',
    'trailing',
    'malformedExtensions',
    'duplicateExtensions',
    'wrongRP',
    'wrongType',
    'wrongChallenge',
    'wrongOrigin',
    'crossOrigin',
    'nullCrossOrigin',
    'topOrigin',
    'duplicateJSON',
  ]) {
    test(
      'rejects independently signed $name',
      () => expect(() => verify(variant(name)), fails),
    );
  }
  test(
    'zero counters, backup-state change and bounded extensions are accepted',
    () {
      verify(vectors['assertion'] as Map<String, Object?>);
      expect(verify(variant('backupStateChanged')).backupState, isFalse);
      verify(variant('validExtensions'));
    },
  );
  test('nonzero counters must increase', () {
    final one = verify(variant('counterOne'));
    expect(verify(variant('counterTwo'), previous: one).signCount, 2);
    expect(() => verify(variant('counterOne'), previous: one), fails);
    expect(
      () => verify(vectors['assertion'] as Map<String, Object?>, previous: one),
      fails,
    );
  });
  test('wrong ID, handle, signature and public key fail', () {
    final response = vectors['assertion'] as Map<String, Object?>;
    expect(() => verify(response, id: Uint8List(32)), fails);
    expect(() => verify(response, user: Uint8List(32)), fails);
    final signature = bytes(response['signature']);
    signature[signature.length - 1] ^= 1;
    expect(() => verify(response, signature: signature), fails);
    final cose = bytes(vectors['publicKeyCose']);
    cose[cose.length - 1] ^= 1;
    expect(() => verify(response, cose: cose), fails);
  });
  test(
    'registration rejects absent PRF without accepting ordinary sign-in',
    () {
      expect(
        () => verifier.registration(
          challenge: bytes(vectors['challenge']),
          credentialId: registered.credentialId,
          clientDataJSON: bytes(section('registration')['clientDataJSON']),
          attestationObject: bytes(
            section('registration')['attestationObject'],
          ),
          prfEnabled: false,
        ),
        throwsA(
          isA<PasskeyException>().having(
            (e) => e.code,
            'code',
            PasskeyErrorCode.prfUnavailable,
          ),
        ),
      );
    },
  );
  test('every truncated registration prefix fails', () {
    final att = bytes(section('registration')['attestationObject']);
    for (var i = 0; i < att.length; i++) {
      expect(
        () => verifier.registration(
          challenge: bytes(vectors['challenge']),
          credentialId: registered.credentialId,
          clientDataJSON: bytes(section('registration')['clientDataJSON']),
          attestationObject: Uint8List.sublistView(att, 0, i),
          prfEnabled: true,
        ),
        fails,
        reason: 'prefix $i',
      );
    }
  });
  test('strict DER rejects trailing, negative, zero and padded integers', () {
    for (final signature in [
      <int>[],
      [48, 6, 2, 1, 128, 2, 1, 1],
      [48, 7, 2, 2, 0, 1, 2, 1, 1],
      [48, 6, 2, 1, 0, 2, 1, 1],
      [48, 6, 2, 1, 1, 2, 1, 0],
    ]) {
      expect(
        () => verify(
          vectors['assertion'] as Map<String, Object?>,
          signature: Uint8List.fromList(signature),
        ),
        fails,
      );
    }
    final valid = bytes(section('assertion')['signature']);
    expect(
      () => verify(
        vectors['assertion'] as Map<String, Object?>,
        signature: Uint8List.fromList([...valid, 0]),
      ),
      fails,
    );
  });
  test(
    'origin configuration never accepts implicit aliases or production HTTP',
    () {
      for (final origin in [
        'http://vault.example.com',
        'https://vault.example.com/',
        'https://vault.example.com/path',
        'https://vault.example.com@evil.test',
        'https://evilvault.example.com',
        'https://vault.example.com?x',
        'https://vault.example.com#x',
      ]) {
        expect(
          () => WebAuthnVerifier(domain: 'vault.example.com', origin: origin),
          throwsA(isA<PasskeyException>()),
        );
      }
      expect(
        () => WebAuthnVerifier(
          domain: 'localhost',
          origin: 'http://localhost:8765',
        ),
        throwsA(isA<PasskeyException>()),
      );
      WebAuthnVerifier(
        domain: 'localhost',
        origin: 'http://localhost:8765',
        allowLocalhost: true,
      );
    },
  );
  test(
    'CBOR rejects duplicate keys, indefinite lengths, overlong lengths and resource abuse',
    () {
      for (final cbor in [
        <int>[0xa2, 1, 1, 1, 2],
        [0x9f, 0xff],
        [0x18, 1],
        [0x1b, 0, 0, 0, 0, 0, 0, 0, 1],
        [0x61, 0xff],
        [0xc0, 0],
        [0xa1, 0x41, 1, 1],
        [...List.filled(10, 0x81), 0],
        [0x82, 1],
        [0, 0],
      ]) {
        expect(
          () => BoundedCbor(Uint8List.fromList(cbor)).readAll(),
          throwsFormatException,
        );
      }
      expect(() => BoundedCbor(Uint8List(16385)), throwsFormatException);
    },
  );
  test('client JSON bounds apply to ignored members too', () {
    for (final input in [
      '{"x":1,"x":2}',
      '{"x":{"a":1,"a":2}}',
      '{"x":${List.filled(10, '[').join()}0${List.filled(10, ']').join()}}',
      '{"x":1e999}',
      '{"x":1,}',
      '{"x":[1,]}',
      '{}{}',
    ]) {
      expect(
        () => parseClientData(Uint8List.fromList(utf8.encode(input))),
        throwsFormatException,
      );
    }
    expect(
      parseClientData(
        Uint8List.fromList(utf8.encode('{"x":[true,false,null,1.5,"a\\"b"]}')),
      )['x'],
      [true, false, null, 1.5, 'a"b'],
    );
  });
}
