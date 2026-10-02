import 'dart:async';
import 'dart:typed_data';
import 'package:test/test.dart';
import '../../tool/demo/channel.dart';

void main() {
  test(
    'private pipe frames survive fragmentation and consume owned bytes',
    () async {
      final packet = demoPublicFrame({'kind': 'nativeResponse', 'id': 1});
      ByteData.sublistView(packet).setUint32(4, 32, Endian.little);
      final chunks = <Uint8List>[
        Uint8List.fromList(packet.sublist(0, 3)),
        Uint8List.fromList(packet.sublist(3)),
        Uint8List(11)..fillRange(0, 11, 7),
        Uint8List(21)..fillRange(0, 21, 7),
      ];
      final frames = await readDemoFrames(Stream.fromIterable(chunks)).toList();
      expect(frames.single.message['id'], 1);
      expect(frames.single.secret, everyElement(7));
      for (final chunk in chunks) {
        expect(chunk, everyElement(0));
      }
      frames.single.clear();
      expect(frames.single.secret, everyElement(0));
    },
  );
  test(
    'truncated secret and malformed metadata fail without yielding bytes',
    () async {
      final packet = demoPublicFrame({'kind': 'nativeResponse'});
      ByteData.sublistView(packet).setUint32(4, 32, Endian.little);
      final partial = Uint8List.fromList([...packet, 1, 2, 3]);
      await expectLater(
        readDemoFrames(Stream.value(partial)).toList(),
        throwsFormatException,
      );
      expect(partial, everyElement(0));
      final bad = Uint8List(8 + 1 + 32);
      ByteData.sublistView(bad).setUint32(0, 1, Endian.little);
      ByteData.sublistView(bad).setUint32(4, 32, Endian.little);
      bad[8] = 123;
      bad.fillRange(9, bad.length, 8);
      await expectLater(
        readDemoFrames(Stream.value(bad)).toList(),
        throwsFormatException,
      );
      expect(bad, everyElement(0));
    },
  );
  test('outsize frame rejected before allocation', () async {
    final header = Uint8List(8);
    ByteData.sublistView(header).setUint32(0, 0xffffffff, Endian.little);
    await expectLater(
      readDemoFrames(Stream.value(header)).toList(),
      throwsFormatException,
    );
  });
}
