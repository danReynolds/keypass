import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

/// Demo-only private pipe framing. Secrets never enter JSON or a command line.
/// uint32 LE: JSON length, then binary-secret length (0 or 32), then both bodies.
final class DemoFrame {
  DemoFrame(this.message, this.secret);
  final Map<String, Object?> message;
  final Uint8List secret;
  void clear() => secret.fillRange(0, secret.length, 0);
}

Stream<DemoFrame> readDemoFrames(Stream<List<int>> input) async* {
  final iterator = StreamIterator(input);
  List<int> chunk = <int>[];
  var offset = 0;
  Future<Uint8List?> read(int length, {bool allowEof = false}) async {
    final output = Uint8List(length);
    var written = 0;
    try {
      while (written < length) {
        if (offset == chunk.length) {
          if (!await iterator.moveNext()) {
            if (allowEof && written == 0) return null;
            throw const FormatException('Incomplete demo frame');
          }
          chunk = iterator.current;
          offset = 0;
          if (chunk.isEmpty) continue;
        }
        final count = (length - written) < (chunk.length - offset)
            ? length - written
            : chunk.length - offset;
        output.setRange(written, written + count, chunk, offset);
        chunk.fillRange(offset, offset + count, 0);
        offset += count;
        written += count;
      }
      return output;
    } catch (_) {
      output.fillRange(0, output.length, 0);
      rethrow;
    }
  }

  try {
    while (true) {
      final header = await read(8, allowEof: true);
      if (header == null) return;
      final data = ByteData.sublistView(header);
      final jsonLength = data.getUint32(0, Endian.little);
      final secretLength = data.getUint32(4, Endian.little);
      if (jsonLength == 0 ||
          jsonLength > 262144 ||
          ![0, 32].contains(secretLength)) {
        throw const FormatException('Invalid demo frame');
      }
      final jsonBytes = (await read(jsonLength))!;
      // Parse public metadata before reading any secret into its own allocation.
      final message = jsonDecode(utf8.decode(jsonBytes));
      if (message is! Map<String, dynamic>) {
        throw const FormatException('Invalid demo frame');
      }
      final secret = (await read(secretLength))!;
      yield DemoFrame(message, secret);
    }
  } finally {
    chunk.fillRange(offset, chunk.length, 0);
    await iterator.cancel();
  }
}

Uint8List demoPublicFrame(Map<String, Object?> message) {
  final json = utf8.encode(jsonEncode(message));
  if (json.isEmpty || json.length > 262144) {
    throw const FormatException('Invalid demo frame');
  }
  final packet = Uint8List(8 + json.length);
  ByteData.sublistView(packet).setUint32(0, json.length, Endian.little);
  packet.setRange(8, packet.length, json);
  return packet;
}
