import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import '../tool/browser/bridge.dart';
import '../tool/browser/channel.dart';
import '../tool/browser/restart_check.dart';
import '../tool/browser/evidence.dart';

void main() {
  test(
    'restart check binds PRF and metadata without retaining secret bytes',
    () async {
      final secret = randomBytes(32);
      final binding = <String, Object?>{
        'domain': 'vault.example.com',
        'credential': 'one',
      };
      final saved = await createRestartCheck(secret, binding);
      await verifyRestartCheck(Uint8List.fromList(secret), binding, saved);
      final wrong = Uint8List.fromList(secret);
      wrong[0] ^= 1;
      await expectLater(
        verifyRestartCheck(wrong, binding, saved),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      await expectLater(
        verifyRestartCheck(secret, {...binding, 'credential': 'two'}, saved),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      secret.fillRange(0, secret.length, 0);
      wrong.fillRange(0, wrong.length, 0);
    },
  );
  Map<String, Object?> request() => {
    'version': 1,
    'domain': 'vault.example.com',
    'userId': encodeBytes(randomBytes(32)),
    'input': encodeBytes(randomBytes(32)),
    'registrationChallenge': encodeBytes(randomBytes(32)),
    'challenges': [encodeBytes(randomBytes(32)), encodeBytes(randomBytes(32))],
  };
  for (final mode in [
    'success',
    'reject',
    'tamper',
    'cancel',
    'evidence',
    'badEvidence',
  ]) {
    test(
      'Node WebCrypto -> Dart paired HTTP round trip: $mode',
      () async {
        String? code;
        final withEvidence = mode == 'evidence' || mode == 'badEvidence';
        final operation = request();
        if (withEvidence) operation['evidenceVersion'] = 1;
        final bridge = await ProbeBridge.start(
          helper: Uri.parse('https://vault.example.com/probe.html'),
          domain: 'vault.example.com',
          request: operation,
          confirmPairing: (value) async {
            code = value;
            return mode != 'reject';
          },
        );
        final receipt = mode == 'success' || withEvidence
            ? bridge.result
            : expectLater(
                bridge.result,
                throwsStateError,
              ).then((_) => Uint8List(0));
        addTearDown(bridge.close);
        final peer = await Process.run('node', [
          'test/browser/peer.mjs',
          jsonEncode({
            'endpoint': bridge.endpoint.toString(),
            'session': bridge.session,
            'key': encodeBytes(bridge.publicKey),
            'domain': bridge.domain,
            'origin': bridge.helper.origin,
            'reject': mode == 'reject',
            'tamper': mode == 'tamper',
            'corruptEvidence': mode == 'badEvidence',
            'cancel': mode == 'cancel',
          }),
        ]);
        expect(peer.exitCode, 0, reason: peer.stderr.toString());
        expect((jsonDecode(peer.stdout.toString()) as Map)['code'], code);
        final result = await receipt;
        if (withEvidence) {
          final metadata = (jsonDecode(utf8.decode(result.sublist(33))) as Map)
              .cast<String, Object?>();
          Map<String, Object?> verify() => verifyProbeEvidence(
            request: operation,
            origin: bridge.helper.origin,
            metadata: metadata,
          );
          try {
            if (mode == 'badEvidence') {
              expect(verify, throwsA(isA<Exception>()));
            } else {
              expect(verify()['domain'], bridge.domain);
              final assertions = metadata['assertions'] as List;
              final swap = assertions[0];
              assertions[0] = assertions[1];
              assertions[1] = swap;
              expect(verify, throwsA(isA<Exception>()));
            }
          } finally {
            result.fillRange(0, result.length, 0);
          }
        } else if (mode == 'success') {
          expect(result.sublist(1, 33), List.filled(32, 42));
          expect(
            (jsonDecode(utf8.decode(result.sublist(33))) as Map)['domain'],
            bridge.domain,
          );
          result.fillRange(0, result.length, 0);
        }
      },
      timeout: const Timeout(Duration(seconds: 20)),
    );
  }
  test('unpaired session expires without accepting secret material', () async {
    final bridge = await ProbeBridge.start(
      helper: Uri.parse('https://vault.example.com/probe.html'),
      domain: 'vault.example.com',
      request: request(),
      confirmPairing: (_) async => false,
      deadline: const Duration(milliseconds: 20),
    );
    await expectLater(bridge.result, throwsStateError);
    await bridge.close();
  });
  test(
    'HTTP helper requires explicit localhost-only development opt-in',
    () async {
      for (final helper in [
        'http://vault.example.com/probe.html',
        'https://other.example.com/probe.html',
        'https://vault.example.com/probe.html#secret',
        'https://vault.example.com/probe.html?secret=1',
        'https://user:password@vault.example.com/probe.html',
      ]) {
        await expectLater(
          ProbeBridge.start(
            helper: Uri.parse(helper),
            domain: 'vault.example.com',
            request: request(),
            confirmPairing: (_) async => true,
            allowLoopback: true,
          ),
          throwsArgumentError,
        );
      }
    },
  );
  test(
    'Dart channel rejects tampering, replay, reflection and malformed frames',
    () async {
      final a = await X25519().newKeyPair(), b = await X25519().newKeyPair();
      final ap = await a.extractPublicKey(), bp = await b.extractPublicKey();
      final context = transcript(
        origin: 'https://vault.example.com',
        domain: 'vault.example.com',
        session: 'unique',
        serverPublicKey: ap.bytes,
        browserPublicKey: bp.bytes,
      );
      final server = await ProbeChannel.derive(
        keyPair: a,
        remotePublicKey: bp.bytes,
        transcript: context,
        server: true,
      );
      final browser = await ProbeChannel.derive(
        keyPair: b,
        remotePublicKey: ap.bytes,
        transcript: context,
        server: false,
      );
      addTearDown(() {
        a.destroy();
        b.destroy();
        server.close();
        browser.close();
      });
      expect(server.code, browser.code);
      final frame = await server.seal([1, 2, 3]);
      final bad = Uint8List.fromList(frame);
      bad[bad.length - 1] ^= 1;
      await expectLater(
        browser.open(bad),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      await expectLater(
        server.open(frame),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
      expect(await browser.open(frame), [1, 2, 3]);
      await expectLater(browser.open(frame), throwsStateError);
      await expectLater(browser.open(Uint8List(19)), throwsStateError);
      server.close();
      await expectLater(server.seal([1]), throwsStateError);
    },
  );
}
