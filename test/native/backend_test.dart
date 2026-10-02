import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:keypass/keypass_backend.dart';
import 'package:keypass/src/native/backend.dart';
import 'package:test/test.dart';

final class FixtureTransport implements NativeTransport {
  FixtureTransport(this.response);
  String platform = 'apple';
  String origin = 'https://vault.example.com';
  NativeReply response;
  Map<String, Object?>? last;
  @override
  Future<NativeReply> exchange(
    Map<String, Object?> request,
    PasskeyCancellation cancellation,
  ) async {
    last = request;
    if (request['operation'] == 'availability') {
      return NativeReply({
        'platform': platform,
        'origin': origin,
        'multiple': true,
      });
    }
    return response;
  }

  @override
  Future<void> dispose() async {}
}

void main() {
  late Map<String, dynamic> fixture;
  Uint8List b(String name) =>
      base64Url.decode(base64Url.normalize(fixture[name] as String));
  setUpAll(() async {
    final result = await Process.run('node', ['test/webauthn/vectors.mjs']);
    expect(result.exitCode, 0, reason: result.stderr.toString());
    fixture = jsonDecode(result.stdout as String) as Map<String, dynamic>;
  });
  Future<(NativePasskeyBackend, FixtureTransport, PasskeyBinding)>
  enroll() async {
    final transport = FixtureTransport(
      NativeReply({
        ...fixture['registration'] as Map<String, dynamic>,
        'credentialId': fixture['credentialId'],
        'prfEnabled': true,
      }),
    );
    final backend = NativePasskeyBackend(
      transport,
      domain: fixture['domain'] as String,
    );
    expect((await backend.availability()).canAttempt, isTrue);
    final binding = await backend.register(
      PasskeyRegistrationRequest(
        domain: fixture['domain'] as String,
        displayName: 'Fixture',
        label: 'Fixture',
        userId: b('userId'),
        challenge: b('challenge'),
        input: Uint8List.fromList([1, 2, 3]),
      ),
      PasskeyCancellation(),
    );
    return (backend, transport, binding);
  }

  NativeReply assertion([String? variant]) => NativeReply({
    ...(variant == null
            ? fixture['assertion']
            : (fixture['variants'] as Map<String, dynamic>)[variant])
        as Map<String, dynamic>,
    'credentialId': fixture['credentialId'],
    'userHandle': fixture['userId'],
  }, Uint8List(32)..fillRange(0, 32, 9));

  test(
    'raw registration and assertion verified before transferring PRF bytes',
    () async {
      final (backend, transport, binding) = await enroll();
      expect(binding.authenticatorState.backupEligible, isTrue);
      transport.response = assertion('counterOne');
      final result = await backend.evaluate(
        PasskeyEvaluationRequest(
          bindings: [binding],
          challenge: b('challenge'),
        ),
        PasskeyCancellation(),
      );
      expect(result.state.signCount, 1);
      expect(result.secret, everyElement(9));
      final options = transport.last!['publicKey'] as Map;
      expect(
        ((options['extensions'] as Map)['prf'] as Map)['evalByCredential'],
        {
          fixture['credentialId']: {'first': 'AQID'},
        },
      );
      result.clear();
      expect(transport.response.secret, everyElement(0));
    },
  );
  for (final variant in [
    'wrongChallenge',
    'wrongOrigin',
    'missingUV',
    'changedBackupEligibility',
  ]) {
    test('rejects signed $variant and clears native secret', () async {
      final (backend, transport, binding) = await enroll();
      transport.response = assertion(variant);
      await expectLater(
        backend.evaluate(
          PasskeyEvaluationRequest(
            bindings: [binding],
            challenge: b('challenge'),
          ),
          PasskeyCancellation(),
        ),
        throwsA(
          isA<PasskeyException>().having(
            (e) => e.code,
            'code',
            PasskeyErrorCode.verificationFailed,
          ),
        ),
      );
      expect(transport.response.secret, everyElement(0));
    });
  }
  test(
    'counter state survives serialization and rejects replay after restart',
    () async {
      final (backend, transport, binding) = await enroll();
      transport.response = assertion('counterOne');
      final first = await backend.evaluate(
        PasskeyEvaluationRequest(
          bindings: [binding],
          challenge: b('challenge'),
        ),
        PasskeyCancellation(),
      );
      final saved = PasskeyBinding.fromJson(
        binding.withState(first.state).toJson(),
      );
      first.clear();
      transport.response = assertion('counterOne');
      await expectLater(
        backend.evaluate(
          PasskeyEvaluationRequest(
            bindings: [saved],
            challenge: b('challenge'),
          ),
          PasskeyCancellation(),
        ),
        throwsA(isA<PasskeyException>()),
      );
      expect(transport.response.secret, everyElement(0));
      transport.response = assertion('counterTwo');
      final next = await backend.evaluate(
        PasskeyEvaluationRequest(bindings: [saved], challenge: b('challenge')),
        PasskeyCancellation(),
      );
      expect(next.state.signCount, 2);
      next.clear();
    },
  );
  test('valid authentication without PRF is not encryption access', () async {
    final (backend, transport, binding) = await enroll();
    transport.response = NativeReply(assertion().metadata);
    await expectLater(
      backend.evaluate(
        PasskeyEvaluationRequest(
          bindings: [binding],
          challenge: b('challenge'),
        ),
        PasskeyCancellation(),
      ),
      throwsA(
        isA<PasskeyException>().having(
          (e) => e.code,
          'code',
          PasskeyErrorCode.prfUnavailable,
        ),
      ),
    );
  });
  test(
    'Android uses independently derived signing origin, not a web origin',
    () async {
      final (backend, transport, binding) = await enroll();
      transport.platform = 'android';
      transport.origin =
          'android:apk-key-hash:${encode(Uint8List(32)..fillRange(0, 32, 1))}';
      expect((await backend.availability()).canAttempt, isTrue);
      transport.response = assertion();
      await expectLater(
        backend.evaluate(
          PasskeyEvaluationRequest(
            bindings: [binding],
            challenge: b('challenge'),
          ),
          PasskeyCancellation(),
        ),
        throwsA(isA<PasskeyException>()),
      );
      expect(transport.response.secret, everyElement(0));
      transport.response = assertion('androidOrigin');
      final valid = await backend.evaluate(
        PasskeyEvaluationRequest(
          bindings: [binding],
          challenge: b('challenge'),
        ),
        PasskeyCancellation(),
      );
      expect(valid.secret, everyElement(9));
      valid.clear();
    },
  );
}
