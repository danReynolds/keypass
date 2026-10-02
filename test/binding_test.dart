import 'dart:convert';
import 'dart:typed_data';

import 'package:keypass/keypass_backend.dart';
import 'package:test/test.dart';

import 'support/recording_backend.dart';

void main() {
  test('binding round-trips only versioned public metadata', () {
    final original = binding();
    final json =
        jsonDecode(jsonEncode(original.toJson())) as Map<String, dynamic>;
    final restored = PasskeyBinding.fromJson(json);
    expect(restored.toJson(), original.toJson());
    expect(original.toJson().keys, isNot(contains('secret')));
  });

  test('binding takes immutable snapshots without exposing source buffers', () {
    final input = Uint8List.fromList([3]);
    final id = Uint8List.fromList([4]);
    final saved = PasskeyBinding(
      authenticatorState: binding().authenticatorState,
      domain: 'VAULT.example.com',
      credentialId: id,
      userId: id,
      publicKeyCose: id,
      input: input,
    );
    input[0] = 8;
    id[0] = 9;
    expect(saved.input, [3]);
    expect(saved.credentialId, [4]);
    expect(saved.domain, 'vault.example.com');
    expect(() => saved.input[0] = 5, throwsUnsupportedError);
    expect(
      () => saved.input.buffer.asUint8List()[0] = 5,
      throwsUnsupportedError,
    );
  });

  for (final domain in [
    '',
    'https://example.com',
    'example.com/path',
    'example.com:443',
    'localhost',
    '127.0.0.1',
    'example..com',
    '-bad.example',
    'example.com.',
    ' example.com',
    'exämple.com',
  ]) {
    test('rejects malformed/unsupported RP identity: $domain', () {
      expect(() => binding(domain: domain), throwsA(isA<PasskeyException>()));
    });
  }

  for (final entry in <String, Object?>{
    'version': 1,
    'prf': 'raw-ctap',
    'credentialId': 'AQ==',
    'userId': 4,
    'publicKeyCose': '*',
    'input': '',
  }.entries) {
    test('rejects malformed binding field ${entry.key}', () {
      final json = <String, Object?>{
        ...binding().toJson(),
        entry.key: entry.value,
      };
      expect(
        () => PasskeyBinding.fromJson(json),
        throwsA(isA<PasskeyException>()),
      );
    });
  }

  test('rejects unknown fields and oversized data before decoding', () {
    expect(
      () => PasskeyBinding.fromJson({...binding().toJson(), 'extra': true}),
      throwsA(isA<PasskeyException>()),
    );
    expect(
      () =>
          PasskeyBinding.fromJson({...binding().toJson(), 'input': 'a' * 9999}),
      throwsA(isA<PasskeyException>()),
    );
  });

  test('diagnostics omit identifying metadata', () {
    expect(binding().toString(), 'PasskeyBinding(version: 2)');
    expect(
      const PasskeyException(PasskeyErrorCode.backendFailure).toString(),
      'PasskeyException(backendFailure)',
    );
  });
}
