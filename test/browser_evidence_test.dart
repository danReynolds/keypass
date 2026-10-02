import 'dart:convert';
import 'dart:io';
import '../tool/browser/evidence.dart';
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
  Map<String, Object?> verify({bool reuse = false}) => verifyProbeEvidence(
    request: section(reuse ? 'reuse' : 'request'),
    origin: data['origin'] as String,
    metadata: section(reuse ? 'reuseMetadata' : 'metadata'),
  );
  test(
    'raw enrollment and saved-binding reuse independently verify in Dart',
    () {
      expect(verify(), section('metadata')['binding']);
      expect(verify(reuse: true), verify());
    },
  );
  test(
    'reuse rejects a changed binding even with otherwise valid assertions',
    () {
      (section('reuseMetadata')['binding'] as Map<String, Object?>)['input'] =
          'changed';
      expect(() => verify(reuse: true), throwsFormatException);
    },
  );
  test('reuse never accepts replacement registration', () {
    section('reuseMetadata')['registration'] = section(
      'metadata',
    )['registration'];
    expect(() => verify(reuse: true), throwsFormatException);
  });
  test('missing raw attestation and assertion evidence fail closed', () {
    final metadata = section('metadata');
    final registration = metadata['registration'];
    metadata['registration'] = null;
    expect(verify, throwsFormatException);
    metadata['registration'] = registration;
    (metadata['assertions'] as List).removeLast();
    expect(verify, throwsFormatException);
  });
  test('mismatched request origin and duplicate challenges fail', () {
    expect(
      () => verifyProbeEvidence(
        request: section('request'),
        origin: 'https://sub.vault.example.com',
        metadata: section('metadata'),
      ),
      throwsA(isA<Exception>()),
    );
    final challenges = section('request')['challenges'] as List;
    challenges[1] = challenges[0];
    expect(verify, throwsFormatException);
  });
  test('extension support and canonical encodings are required', () {
    final reg = section('metadata')['registration'] as Map<String, Object?>;
    reg['prfEnabled'] = false;
    expect(verify, throwsFormatException);
    reg['prfEnabled'] = true;
    reg['attestationObject'] = '${reg['attestationObject']}=';
    expect(verify, throwsFormatException);
  });
}
