import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:keypass/src/models.dart';
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
  RandomAccessFile? lock;
  Directory? stage;
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
    final file = File(options['--binding']!).absolute;
    // Hold a separate stable inode while atomically replacing the saved record.
    lock = await File('${file.path}.lock').open(mode: FileMode.append);
    await lock.lock(FileLock.exclusive);
    Map<String, Object?>? binding;
    Map<String, Object?>? saved;
    if (await file.exists()) {
      if (await file.length() > 16384) {
        throw const FormatException('Invalid binding');
      }
      saved = (jsonDecode(await file.readAsString()) as Map)
          .cast<String, Object?>();
      if (saved['version'] != 2) {
        throw const FormatException('Invalid probe file');
      }
      final parsed = PasskeyBinding.fromJson(
        (saved['binding'] as Map).cast<String, Object?>(),
      );
      if (parsed.route != PasskeyRoute.system) {
        throw const FormatException('Wrong route');
      }
      binding = parsed.toJson();
      if (binding['domain'] != options['--rp']) {
        throw const FormatException('Wrong domain');
      }
    }
    final request = <String, Object?>{
      'version': 2,
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
    ).toJson();
    if (binding != null) {
      await verifyRestartCheck(
        Uint8List.sublistView(result, 1, 33),
        binding,
        (saved!['restartCheck'] as Map).cast<String, Object?>(),
      );
      stdout.writeln(
        'Saved encryption check passed: the PRF matches the earlier process.',
      );
    }
    // Bind the updated verification state to the same recovered secret, then
    // publish the record and marker together. Failed verification writes nothing.
    final restart = await createRestartCheck(
      Uint8List.sublistView(result, 1, 33),
      received,
    );
    stage = await file.parent.createTemp('.keypass-probe-');
    final pending = File('${stage.path}/record.json');
    await pending.writeAsString(
      jsonEncode({'version': 2, 'binding': received, 'restartCheck': restart}),
      flush: true,
    );
    await pending.rename(file.path);
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
    await stage?.delete(recursive: true);
    await lock?.close();
    await interrupt?.cancel();
    await lines?.cancel();
    await bridge?.close();
  }
}
