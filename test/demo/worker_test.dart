import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import '../../tool/demo/channel.dart';

void main() {
  for (final configured in [true, false]) {
    test(
      'worker IPC remains open after operation cleanup (configured: $configured)',
      () async {
        final directory = await Directory.systemTemp.createTemp(
          'keypass-worker-',
        );
        final process = await Process.start(Platform.resolvedExecutable, [
          'tool/demo/worker.dart',
          configured ? 'vault.example.com' : '',
          '${directory.path}/unused-marker.json',
        ]);
        final diagnostics = process.stderr.transform(utf8.decoder).join();
        final frames = StreamIterator(readDemoFrames(process.stdout));

        Future<Map<String, Object?>> next() async {
          expect(
            await frames.moveNext().timeout(const Duration(seconds: 15)),
            isTrue,
            reason: 'Worker closed its public protocol unexpectedly',
          );
          final frame = frames.current;
          try {
            expect(frame.secret, isEmpty);
            return frame.message;
          } finally {
            frame.clear();
          }
        }

        try {
          final ready = await next();
          expect(ready['kind'], 'ready');
          expect(ready['configured'], configured);
          for (var i = 0; i < 3; i++) {
            process.stdin.add(
              demoPublicFrame({'kind': 'command', 'command': 'check'}),
            );
            await process.stdin.flush();
            var nativeCalls = 0;
            while (true) {
              final message = await next();
              if (message['kind'] == 'nativeRequest') {
                nativeCalls++;
                final request = message['request'] as Map;
                expect(request['operation'], 'availability');
                expect(request['domain'], 'vault.example.com');
                process.stdin.add(
                  demoPublicFrame({
                    'kind': 'nativeResponse',
                    'id': message['id'],
                    'status': 0,
                    'metadata': {
                      'origin': 'https://vault.example.com',
                      'platform': 'apple',
                      'multiple': true,
                    },
                  }),
                );
                await process.stdin.flush();
              } else if (message['kind'] == 'status') {
                expect(message['code'], isNull);
              } else if (message['kind'] == 'idle') {
                expect(message['saved'], isFalse);
                break;
              } else {
                fail('Unexpected public worker message: ${message['kind']}');
              }
            }
            expect(nativeCalls, 1);
          }
          await process.stdin.close();
          expect(
            await process.exitCode.timeout(const Duration(seconds: 15)),
            0,
            reason: await diagnostics,
          );
          expect(
            File('${directory.path}/unused-marker.json').existsSync(),
            isFalse,
          );
        } finally {
          process.kill();
          await frames.cancel();
          await directory.delete(recursive: true);
        }
      },
    );
  }
}
