import 'dart:async';
import 'dart:io';
import 'package:keypass/keypass.dart';
import '../../tool/hardware_demo.dart' as demo;

/// Executed only by the synthetic PTY driver; it never opens a hardware client.
Future<void> main(List<String> args) async {
  final signal = PasskeyCancellation();
  final pending = demo.readPin(signal);
  stdout.writeln('SYNTHETIC_READY');
  if (args.single == 'cancel') {
    Timer(const Duration(milliseconds: 50), signal.cancel);
  }
  final bytes = await pending;
  try {
    if (args.single == 'cancel') {
      if (bytes != null) throw StateError('Expected cancellation');
    } else {
      const expected = [
        115,
        121,
        110,
        116,
        104,
        101,
        116,
        105,
        99,
        45,
        116,
        101,
        115,
        116,
        45,
        112,
        105,
        110,
      ];
      if (bytes == null || bytes.length != expected.length) {
        throw StateError('Wrong synthetic input');
      }
      for (var i = 0; i < expected.length; ++i) {
        if (bytes[i] != expected[i]) throw StateError('Wrong synthetic input');
      }
    }
    stdout.writeln('SYNTHETIC_OK');
  } finally {
    bytes?.fillRange(0, bytes.length, 0);
  }
}
