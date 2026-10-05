import 'dart:convert';
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

const hardwareAsset = 'src/hardware/bindings.dart';

Future<void> main(List<String> arguments) => build(arguments, buildHardware);

Future<void> buildHardware(BuildInput input, BuildOutputBuilder output) async {
  if (!input.config.buildCodeAssets) return;
  final config = input.config.code;
  // Apple/Android app hosts retain their existing native linking and lifecycle.
  // Windows has no direct USB adapter yet. These targets must not build the
  // desktop libfido2 implementation on the machine running the hook.
  if (config.targetOS != OS.macOS && config.targetOS != OS.linux) return;
  if (config.targetOS != OS.current ||
      config.targetArchitecture != Architecture.current) {
    throw UnsupportedError(
      'Keypass desktop hardware assets currently require a native build for '
      '${config.targetOS}/${config.targetArchitecture}. Run the build on that '
      'platform; host libraries cannot be used for a different target.',
    );
  }
  final root = input.packageRoot;
  final native = input.outputDirectory.resolve('native/');
  final bundle = input.outputDirectory.resolve('bundle/');
  await Directory.fromUri(bundle).create(recursive: true);
  final files = await Directory.fromUri(root.resolve('native/hardware/'))
      .list(recursive: true, followLinks: false)
      .where((entry) => entry is File)
      .map((entry) => entry.uri)
      .toList();
  output.dependencies.addAll([
    ...files,
    root.resolve('hook/bundle.py'),
    root.resolve('pubspec.yaml'),
  ]);
  await run('pkg-config', ['--atleast-version=1.16', 'libfido2']);
  await run('pkg-config', ['--atleast-version=3', 'libcrypto']);
  // Dart can reuse this output directory when a Git dependency moves to a new
  // checkout. CMake's cache embeds the old absolute source path. Fresh configure
  // metadata avoids that mismatch without discarding downloads/build outputs.
  final cache = File.fromUri(native.resolve('CMakeCache.txt'));
  if (await cache.exists()) await cache.delete();
  final metadata = Directory.fromUri(native.resolve('CMakeFiles/'));
  if (await metadata.exists()) await metadata.delete(recursive: true);
  await run('cmake', [
    '-S',
    root.resolve('native/hardware/').toFilePath(),
    '-B',
    native.toFilePath(),
    '-DCMAKE_BUILD_TYPE=Release',
    '-DBUILD_TESTING=OFF',
    if (config.targetOS == OS.macOS)
      '-DCMAKE_OSX_DEPLOYMENT_TARGET=${config.macOS.targetVersion}',
  ]);
  await run('cmake', ['--build', native.toFilePath(), '--parallel', '4']);
  final library = config.targetOS == OS.macOS
      ? 'libkeypass_hardware.dylib'
      : 'libkeypass_hardware.so';
  final result =
      jsonDecode(
            await run('python3', [
              root.resolve('hook/bundle.py').toFilePath(),
              native.resolve(library).toFilePath(),
              bundle.toFilePath(),
            ]),
          )
          as Map<String, dynamic>;
  for (final path in (result['inputs'] as List).cast<String>()) {
    output.dependencies.add(Uri.file(path));
  }
  for (final name in (result['libraries'] as List).cast<String>()) {
    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: name == library ? hardwareAsset : 'hardware/$name',
        linkMode: DynamicLoadingBundled(),
        file: bundle.resolve(name),
      ),
    );
  }
}

Future<String> run(String executable, List<String> arguments) async {
  final ProcessResult result;
  try {
    result = await Process.run(executable, arguments);
  } on ProcessException {
    throw StateError(
      'Keypass native build needs $executable on PATH. '
      'See the desktop prerequisites in package:keypass/doc/build-hooks.md.',
    );
  }
  if (result.exitCode != 0) {
    throw StateError(
      'Keypass native build failed in $executable '
      '(exit ${result.exitCode}).\n${result.stdout}\n${result.stderr}\n'
      'See package:keypass/doc/build-hooks.md for desktop prerequisites.',
    );
  }
  return result.stdout as String;
}
