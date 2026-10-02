import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'browser/bridge.dart';
import 'browser/channel.dart';
import 'browser/restart_check.dart';
import 'browser/evidence.dart';

// Deliberately outside lib/: this does not enable Keypass() or unlock a vault.
Future<void> main(List<String> args) async {
  if (args.isEmpty || args.contains('--help')) {
    stdout.writeln(
      'Usage: dart run tool/browser_probe.dart --helper HTTPS_URL '
      '--rp DOMAIN --binding FILE [--allow-loopback]\n'
      'Existing FILE: reuse test passkey. Missing FILE: create a test passkey.\n'
      'The file contains public metadata and an encrypted test marker. No vault access.',
    );
    return;
  }
  ProbeBridge? bridge;
  StreamIterator<String>? lines;
  StreamSubscription<ProcessSignal>? interrupt;
  Uint8List? result;
  try {
    final options = <String, String>{};
    var allowLoopback = false;
    for (var i = 0; i < args.length; i++) {
      if (args[i] == '--allow-loopback') {
        allowLoopback = true;
      } else if (['--helper', '--rp', '--binding'].contains(args[i]) &&
          !options.containsKey(args[i]) &&
          i + 1 < args.length) {
        options[args[i]] = args[++i];
      } else {
        throw const FormatException('Invalid argument');
      }
    }
    if (options.length != 3 || !stdin.hasTerminal) {
      throw const FormatException(
        'Helper, RP, binding path and interactive terminal required',
      );
    }
    final file = File(options['--binding']!);
    Map<String, Object?>? binding;
    Map<String, Object?>? saved;
    if (await file.exists()) {
      if (await file.length() > 16384) {
        throw const FormatException('Invalid binding');
      }
      saved = (jsonDecode(await file.readAsString()) as Map)
          .cast<String, Object?>();
      if (saved['version'] != 1) {
        throw const FormatException('Invalid probe file');
      }
      binding = (saved['binding'] as Map).cast<String, Object?>();
      if (binding['domain'] != options['--rp']) {
        throw const FormatException('Wrong domain');
      }
    }
    final request = <String, Object?>{
      'version': 1,
      'evidenceVersion': 1,
      'domain': options['--rp'],
      'binding': binding,
      'input': binding?['input'] ?? encodeBytes(randomBytes(32)),
      'userId': binding?['userId'] ?? encodeBytes(randomBytes(32)),
      'registrationChallenge': encodeBytes(randomBytes(32)),
      'challenges': [
        encodeBytes(randomBytes(32)),
        encodeBytes(randomBytes(32)),
      ],
    };
    lines = StreamIterator(
      stdin.transform(utf8.decoder).transform(const LineSplitter()),
    );
    bridge = await ProbeBridge.start(
      helper: Uri.parse(options['--helper']!),
      domain: options['--rp']!,
      request: request,
      allowLoopback: allowLoopback,
      confirmPairing: (code) async {
        stdout.writeln(
          '\nCompare every group with the browser:\n$code\n'
          'If all groups match, type yes here and approve in the browser.',
        );
        final inputLines = lines!;
        return await inputLines.moveNext() &&
            inputLines.current.trim() == 'yes';
      },
    );
    interrupt = ProcessSignal.sigint.watch().listen(
      (_) => unawaited(bridge!.close()),
    );
    stdout.writeln(
      'Experimental browser PRF probe; no vault access.\nOpen this public bootstrap URL in your browser:\n${bridge.launchUrl}',
    );
    result = await bridge.result;
    final received = verifyProbeEvidence(
      request: request,
      origin: Uri.parse(options['--helper']!).origin,
      metadata: (jsonDecode(utf8.decode(result.sublist(33))) as Map)
          .cast<String, Object?>(),
      allowLocalhost: allowLoopback,
    );
    if (received['version'] != 1 ||
        received['domain'] != options['--rp'] ||
        received['input'] != request['input'] ||
        received['userId'] != request['userId']) {
      throw const FormatException('Wrong probe binding');
    }
    if (binding == null) {
      // Do not overwrite a file another process created during enrollment.
      final restart = await createRestartCheck(
        Uint8List.sublistView(result, 1, 33),
        received,
      );
      await file.create(exclusive: true);
      await file.writeAsString(
        jsonEncode({
          'version': 1,
          'binding': received,
          'restartCheck': restart,
        }),
        flush: true,
      );
    } else {
      if (jsonEncode(received) != jsonEncode(binding)) {
        throw const FormatException('Changed probe binding');
      }
      await verifyRestartCheck(
        Uint8List.sublistView(result, 1, 33),
        received,
        (saved!['restartCheck'] as Map).cast<String, Object?>(),
      );
      stdout.writeln(
        'Saved encryption check passed: the PRF matches the earlier process.',
      );
    }
    stdout.writeln(
      'Received 32 PRF bytes over the paired encrypted channel.\n'
      'Dart independently verified both assertion signatures and ceremony context.\n'
      'The browser checked equal PRF output across both evaluations.\n'
      'Test binding and encrypted marker saved; secret buffer will now be cleared.\n'
      'Run the same command after restart to reuse this test credential.',
    );
  } catch (_) {
    stderr.writeln(
      'Probe stopped without opening a vault. Check configuration, '
      'browser/PRF support and pairing. A created test passkey may remain.',
    );
    exitCode = 1;
  } finally {
    result?.fillRange(0, result.length, 0);
    await interrupt?.cancel();
    await lines?.cancel();
    await bridge?.close();
  }
}
