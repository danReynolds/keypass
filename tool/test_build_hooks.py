#!/usr/bin/env python3
"""Prove transitive Dart run/test-free ABI and a relocated CLI asset bundle.

No hardware enumeration, PIN input, credentials or vault access is performed.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

repo = Path(__file__).resolve().parent.parent
dart = os.environ.get('DART', 'dart')
probe = '''import 'package:keypass/keypass_backend.dart';
import 'package:keypass/src/hardware/bindings.dart';
import 'package:keypass/src/hardware/ffi_transport.dart';
Future<void> main() async {
  if (hardwareAbiVersion() != 1) throw StateError('wrong ABI');
  final transport = HardwareFfiTransport(const HardwareInteraction());
  try {
    for (var i = 0; i < 2; i++) {
      try {
        await transport.exchange({'operation': 'abi_probe'}, PasskeyCancellation());
        throw StateError('unexpected success');
      } on PasskeyException catch (error) {
        if (error.code != PasskeyErrorCode.invalidRequest) rethrow;
      }
    }
  } finally { await transport.dispose(); }
  print('asset ABI and worker passed');
}
'''
with tempfile.TemporaryDirectory(prefix='keypass assets ') as temporary:
    root = Path(temporary)
    # A separate dependency package proves that consumers need no hook/config.
    bridge = root / 'bridge'
    (bridge / 'lib').mkdir(parents=True)
    (bridge / 'pubspec.yaml').write_text(f'''name: keypass_bridge
environment:
  sdk: ^3.11.0
dependencies:
  keypass:
    path: {repo}
''')
    (bridge / 'lib/bridge.dart').write_text(probe)
    app = root / 'app'
    (app / 'bin').mkdir(parents=True)
    (app / 'pubspec.yaml').write_text(f'''name: asset_consumer
environment:
  sdk: ^3.11.0
dependencies:
  keypass_bridge:
    path: {bridge}
''')
    entry = app / 'bin/asset_consumer.dart'
    entry.write_text("import 'package:keypass_bridge/bridge.dart' as bridge;\nFuture<void> main() => bridge.main();\n")
    def run(args, cwd=app):
        result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=240)
        if result.returncode:
            raise RuntimeError(f'{args[0]} failed:\n{result.stdout}\n{result.stderr}')
        return result.stdout
    run([dart, '--suppress-analytics', 'pub', 'get', '--offline'])
    # First prepare in the owning package; subsequent runs reuse its assets.
    for _ in range(2):
        actual = run([dart, '--suppress-analytics', 'run', str(entry)])
        assert actual.rstrip().endswith('asset ABI and worker passed'), actual
    print('PASS: transitive hook and cached Dart runs')
    run([dart, '--suppress-analytics', 'build', 'cli', '-o', str(root / 'built')])
    installed = root / 'relocated bundle'
    shutil.copytree(root / 'built/bundle', installed)
    libraries = list((installed / 'lib').iterdir())
    assert len(libraries) == 4, libraries
    # The finished application must not need the original build output.
    shutil.rmtree(root / 'built')
    binary = installed / 'bin/asset_consumer'
    assert run([str(binary)], cwd=root).strip() == 'asset ABI and worker passed'
    link = root / 'asset-consumer'
    link.symlink_to(binary)
    assert run([str(link)], cwd=root).strip() == 'asset ABI and worker passed'
    print('PASS: relocated CLI bundle and symlink; four native libraries')
