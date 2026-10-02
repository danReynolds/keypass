import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:keypass/keypass.dart';
// Shared, Flutter-free encrypted-marker fixture; not an SDK dependency.
// ignore: avoid_relative_lib_imports
import '../demo/provider_app/lib/store.dart';

Future<Uint8List?> readPin(PasskeyCancellation cancellation) async {
  if (!stdin.hasTerminal) {
    throw const PasskeyException(PasskeyErrorCode.hostUnavailable);
  }
  final echo = stdin.echoMode, line = stdin.lineMode;
  final complete = Completer<Uint8List?>();
  final buffer = Uint8List(64);
  var used = 0, overflow = false;
  stdin.echoMode = false;
  stdin.lineMode = true;
  StreamSubscription<List<int>>? subscription;
  final cancelled = cancellation.onCancel.listen((_) {
    if (!complete.isCompleted) complete.complete(null);
  });
  try {
    if (cancellation.isCancelled) return null;
    subscription = stdin.listen(
      (chunk) {
        for (final byte in chunk) {
          if (byte == 10 || byte == 13) {
            if (!complete.isCompleted) {
              complete.complete(
                overflow ? null : Uint8List.fromList(buffer.sublist(0, used)),
              );
            }
            break;
          }
          if (used < buffer.length) {
            buffer[used++] = byte;
          } else {
            overflow = true;
          }
        }
        chunk.fillRange(0, chunk.length, 0);
      },
      onDone: () {
        if (!complete.isCompleted) complete.complete(null);
      },
      onError: (Object _) {
        if (!complete.isCompleted) complete.complete(null);
      },
    );
    return await complete.future;
  } finally {
    // Cancelling stdin's stream closes its native descriptor. Restore terminal
    // settings while it is still open, including on cancellation/EOF.
    try {
      stdin.echoMode = echo;
      stdin.lineMode = line;
    } finally {
      await subscription?.cancel();
      await cancelled.cancel();
      buffer.fillRange(0, buffer.length, 0);
      stdout.writeln();
    }
  }
}

Future<void> main(List<String> args) async {
  if (args.isEmpty ||
      !['check', 'enroll', 'unlock'].contains(args[0]) ||
      (args[0] != 'check' && args.length != 2)) {
    stdout.writeln(
      'Usage: hardware_demo check | enroll <marker-file> | unlock <marker-file>',
    );
    stdout.writeln(
      'Uses a disposable encrypted marker and namespace dev.keypass.hardware-demo.',
    );
    return;
  }
  final cancellation = PasskeyCancellation();
  final interrupt = ProcessSignal.sigint.watch().listen(
    (_) => cancellation.cancel(),
  );
  Uint8List? operationPin;
  var touches = 0;
  final started = DateTime.now().toUtc().toIso8601String();
  void receipt(String state, {String? error}) {
    if (args[0] == 'check') return;
    final output = File('${args[1]}.receipt.json');
    output.parent.createSync(recursive: true);
    output.writeAsStringSync(
      jsonEncode({
        'pid': pid,
        'started': started,
        'operation': args[0],
        'state': state,
        'touchRequests': touches,
        'error': error,
        'saved': File(args[1]).existsSync(),
      }),
      flush: true,
    );
  }

  receipt('starting');
  final passkeys = Keypass.hardware(
    rpId: 'dev.keypass.hardware-demo',
    displayName: 'Keypass hardware demo',
    requestPin: (request, signal) async {
      // Demo only: keep one PIN in memory for this explicit enroll/unlock
      // operation, so enrollment's two evaluations need not re-prompt.
      if (operationPin == null) {
        receipt('waitingForPin');
        stdout.write(
          'Security-key PIN (${request.attemptsRemaining} attempts remain; input hidden): ',
        );
        final pin = await readPin(signal);
        if (signal.isCancelled) {
          pin?.fillRange(0, pin.length, 0);
          return null;
        }
        operationPin = pin;
      }
      return operationPin == null ? null : Uint8List.fromList(operationPin!);
    },
    onEvent: (_) {
      touches++;
      receipt('waitingForTouch');
      stdout.writeln('Touch your security key when it flashes.');
    },
  );
  try {
    final available = await passkeys.check();
    if (!available.canAttempt) throw PasskeyException(available.reason!);
    if (args[0] == 'check') {
      stdout.writeln(
        'Hardware backend loaded; a USB security key is connected. No credential operation performed.',
      );
      return;
    }
    final store = DemoStore(File(args[1]));
    if (args[0] == 'enroll') {
      await store.enroll(passkeys, cancellation: cancellation);
      stdout.writeln(
        'Enrollment succeeded: two verified PRF results matched; encrypted marker saved.',
      );
    } else {
      await store.unlock(passkeys, cancellation: cancellation);
      stdout.writeln(
        'Unlock succeeded: the saved marker decrypted in this process.',
      );
    }
    receipt('success');
    stdout.writeln('Process: $pid. No PIN or PRF secret was saved.');
  } on PasskeyException catch (e) {
    receipt('failed', error: e.code.name);
    stderr.writeln('Operation stopped: ${e.code.name}.');
    exitCode = 1;
  } catch (_) {
    receipt('failed', error: 'backendFailure');
    stderr.writeln('Operation failed; the saved marker was not replaced.');
    exitCode = 1;
  } finally {
    operationPin?.fillRange(0, operationPin!.length, 0);
    await interrupt.cancel();
  }
}
