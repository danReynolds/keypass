import 'dart:io';
import 'package:test/test.dart';

void main() {
  if (!Platform.isMacOS && !Platform.isLinux) return;
  late Directory directory;
  late String driver;
  setUpAll(() async {
    directory = await Directory.systemTemp.createTemp('keypass-terminal-');
    driver = '${directory.path}/driver';
    final result = await Process.run('cc', [
      '-Wall',
      '-Wextra',
      '-Werror',
      'test/hardware/terminal_driver.c',
      '-lutil',
      '-o',
      driver,
    ]);
    expect(result.exitCode, 0, reason: result.stderr.toString());
  });
  tearDownAll(() => directory.delete(recursive: true));
  for (final mode in ['input', 'cancel']) {
    test('terminal PIN $mode restores settings before closing stdin', () async {
      final result = await Process.run(driver, [
        Platform.resolvedExecutable,
        File('test/hardware/terminal_probe.dart').absolute.path,
        mode,
      ]);
      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(result.stdout, contains('SYNTHETIC_OK'));
      expect(result.stdout, isNot(contains('synthetic-test-pin')));
    });
  }
}
