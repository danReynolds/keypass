import 'dart:convert';
import 'dart:io';
import '../tool/browser/evidence.dart';
import 'package:keypass/src/models.dart';
import 'package:test/test.dart';

void main() {
  late String fixture;
  late Map<String, Object?> data;
  Map<String, Object?> section(String key) => data[key] as Map<String, Object?>;
  setUpAll(() async {
    final result = await Process.run('node', ['test/browser/evidence.mjs']);
    expect(result.exitCode, 0, reason: result.stderr.toString());
    fixture = result.stdout as String;
  });
  setUp(() => data = jsonDecode(fixture) as Map<String, Object?>);
  PasskeyBinding verify({bool reuse = false}) => verifyProbeEvidence(
    request: section(reuse ? 'reuse' : 'request'),
    origin: data['origin'] as String,
    metadata: section(reuse ? 'reuseMetadata' : 'metadata'),
  );
  test(
    'enrollment and reuse retain SDK records and advance saved counters',
    () {
      final enrolled = verify();
      expect(enrolled.toJson(), section('reuse')['binding']);
      expect(enrolled.authenticatorState.signCount, 2);
      expect(verify(reuse: true).authenticatorState.signCount, 4);
    },
  );
  test('old prototype records are rejected', () {
    section('reuse')['binding'] = {'version': 1};
    expect(() => verify(reuse: true), throwsA(isA<Exception>()));
  });
  test('reuse never accepts replacement registration', () {
    section('reuseMetadata')['registration'] = section(
      'metadata',
    )['registration'];
    expect(() => verify(reuse: true), throwsFormatException);
  });
  test('reuse enforces the counter saved by the previous process', () {
    (section('reuse')['binding'] as Map)['signCount'] = 3;
    expect(() => verify(reuse: true), throwsA(isA<PasskeyException>()));
  });
  test('reuse enforces persisted backup eligibility', () {
    (section('reuse')['binding'] as Map)['backupEligible'] = true;
    expect(() => verify(reuse: true), throwsA(isA<PasskeyException>()));
  });
  test('missing raw registration or assertion evidence fails', () {
    final metadata = section('metadata');
    final registration = metadata['registration'];
    metadata['registration'] = null;
    expect(verify, throwsFormatException);
    metadata['registration'] = registration;
    (metadata['assertions'] as List).removeLast();
    expect(verify, throwsFormatException);
  });
  for (final field in [
    'signature',
    'authenticatorData',
    'clientDataJSON',
    'userHandle',
    'credentialId',
  ]) {
    test('Dart rejects altered $field before the PRF can be used', () {
      final assertion =
          (section('metadata')['assertions'] as List).first as Map;
      final value = base64Url.decode(
        base64Url.normalize(assertion[field] as String),
      );
      value[0] ^= 1;
      assertion[field] = base64Url.encode(value).replaceAll('=', '');
      expect(verify, throwsA(isA<Exception>()));
    });
  }
  test('valid signature cannot excuse a different origin', () {
    expect(
      () => verifyProbeEvidence(
        request: section('request'),
        origin: 'https://sub.vault.example.com',
        metadata: section('metadata'),
      ),
      throwsA(isA<Exception>()),
    );
  });
  test('duplicate challenges fail', () {
    final challenges = section('request')['challenges'] as List;
    challenges[1] = challenges[0];
    expect(verify, throwsFormatException);
  });
  test('extension support and canonical encodings are required', () {
    final reg = section('metadata')['registration'] as Map<String, Object?>;
    reg['prfEnabled'] = false;
    expect(verify, throwsA(isA<PasskeyException>()));
    reg['prfEnabled'] = true;
    reg['attestationObject'] = '${reg['attestationObject']}=';
    expect(verify, throwsFormatException);
  });
  test('system probe rejects hardware records', () {
    final record = section('reuse')['binding'] as Map<String, Object?>;
    record.addAll({
      'version': 3,
      'route': 'hardware',
      'verification': 'required',
      'transports': <String>[],
    });
    expect(() => verify(reuse: true), throwsFormatException);
  });
}
