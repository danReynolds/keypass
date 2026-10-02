import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:keypass/keypass_backend.dart';
// Qualification-only decoration of the same backend used by Keypass.system.
// ignore: implementation_imports
import 'package:keypass/src/native/default_backend.dart';
import 'package:path_provider/path_provider.dart';

import 'provider_progress.dart';
import 'hardware_page.dart';
import 'store.dart';

const domain = String.fromEnvironment(
  'KEYPASS_DOMAIN',
  defaultValue: 'keypass-demo-20260929.web.app',
);

// Optional qualification aid; ordinary builds exercise the public constructor.
const recordProviderProgress = bool.fromEnvironment('KEYPASS_DEMO_PROGRESS');

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const ProviderDemo());
}

class ProviderDemo extends StatelessWidget {
  const ProviderDemo({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Keypass Provider Demo',
    theme: ThemeData(colorSchemeSeed: const Color(0xff315b63)),
    home: const bool.fromEnvironment('KEYPASS_DEMO_HARDWARE')
        ? const HardwarePage()
        : const DemoPage(),
  );
}

class DemoPage extends StatefulWidget {
  const DemoPage({super.key});

  @override
  State<DemoPage> createState() => _DemoPageState();
}

class _DemoPageState extends State<DemoPage> {
  late final _passkeys = recordProviderProgress
      ? keypassWithBackendFactory(
          createBackend: () =>
              ProgressBackend(defaultBackend(domain), _providerProgress),
          rpId: domain,
          displayName: 'Keypass Provider Demo',
        )
      : Keypass.system(rpId: domain, displayName: 'Keypass Provider Demo');
  final _started = DateTime.now().toUtc().toIso8601String();
  DemoStore? _store;
  File? _receipt;
  PasskeyCancellation? _active;
  String _status = 'Opening the saved test…';
  String? _code;
  String _operation = 'startup';
  String? _stage;
  int _registrationsStarted = 0;
  int _evaluationsStarted = 0;
  final _providerCalls = <Map<String, Object?>>[];

  Future<void> _providerProgress(ProviderCall call, ProviderPhase phase) async {
    if (!mounted) return;
    setState(() {
      if (phase == ProviderPhase.started) {
        if (call == ProviderCall.register) {
          _registrationsStarted++;
          _stage = 'Step 1 of 3: create the passkey.';
        } else {
          _evaluationsStarted++;
          _stage = _operation == 'enroll'
              ? 'Step ${_evaluationsStarted + 1} of 3: sign-in check '
                    '$_evaluationsStarted of 2.'
              : 'Sign-in check: recover the saved encryption secret.';
        }
      }
      _providerCalls.add({
        'operation': call.name,
        'phase': phase.name,
        'at': DateTime.now().toUtc().toIso8601String(),
      });
      if (_providerCalls.length > 16) _providerCalls.removeAt(0);
    });
    await _writeReceipt();
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _initialize());
  }

  Future<void> _initialize() async {
    try {
      final support = await getApplicationSupportDirectory();
      // Explicitly separate this FFI host from the original AppKit/worker demo.
      final directory = Directory('${support.path}/provider-test/$domain');
      await directory.create(recursive: true);
      _store = DemoStore(File('${directory.path}/encrypted-test.json'));
      _receipt = File('${directory.path}/receipt.json');
      if (!mounted) return;
      await _run('check', _check);
    } catch (_) {
      if (mounted) {
        setState(() {
          _status = 'Could not open the demo storage.';
          _code = 'demoStorageFailure';
        });
      }
    }
  }

  Future<String> _check(PasskeyCancellation _) async {
    final readiness = await _passkeys.check();
    if (!readiness.canAttempt) throw PasskeyException(readiness.reason!);
    return 'Native FFI connection ready. Select Create or Unlock to test a provider.';
  }

  Future<void> _writeReceipt() async {
    final receipt = _receipt;
    if (receipt == null) return;
    // Public progress only: never serialize secrets, provider responses or binding.
    await receipt.writeAsString(
      jsonEncode({
        'platform': Platform.operatingSystem,
        'pid': pid,
        'started': _started,
        'release': kReleaseMode,
        'transport': 'in-process FFI',
        'client': recordProviderProgress
            ? 'backend integration'
            : 'Keypass.system',
        'providerProgress': recordProviderProgress,
        'domain': domain,
        'operation': _operation,
        'busy': _active != null,
        'saved': _store?.exists ?? false,
        'status': _status,
        'code': _code,
        'stage': _stage,
        'registrationsStarted': recordProviderProgress
            ? _registrationsStarted
            : null,
        'evaluationsStarted': recordProviderProgress
            ? _evaluationsStarted
            : null,
        'providerCalls': recordProviderProgress ? _providerCalls : null,
      }),
      flush: true,
    );
  }

  Future<void> _run(
    String operation,
    Future<String> Function(PasskeyCancellation) action,
  ) async {
    if (_active != null || _store == null) return;
    final signal = PasskeyCancellation();
    setState(() {
      _active = signal;
      _operation = operation;
      _stage = null;
      _registrationsStarted = 0;
      _evaluationsStarted = 0;
      _providerCalls.clear();
      _code = null;
      _status = switch (operation) {
        'enroll' =>
          'Create the test passkey, then approve two verification prompts.',
        'unlock' => 'Approve the passkey prompt to decrypt the saved marker.',
        _ => 'Checking the native FFI connection…',
      };
    });
    try {
      await _writeReceipt();
      final result = await action(signal);
      if (mounted) setState(() => _status = result);
    } on PasskeyException catch (error) {
      if (mounted) {
        setState(() {
          _code = error.code.name;
          _status = switch (error.code) {
            PasskeyErrorCode.prfUnavailable =>
              operation == 'enroll'
                  ? 'The passkey provider did not return the encryption material '
                        'this test needs. Try another provider. A passkey may '
                        'still have been saved in that provider.'
                  : 'The provider did not return encryption material for this '
                        'passkey. The saved test has not been changed.',
            PasskeyErrorCode.hostUnavailable =>
              'The app window was not ready for the passkey prompt. '
                  'Return to this app and try again.',
            _ => 'Operation stopped: ${error.code.name}.',
          };
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          _code = 'demoFailure';
          _status = 'The demo could not complete the operation.';
        });
      }
    } finally {
      if (mounted) setState(() => _active = null);
      try {
        await _writeReceipt();
      } catch (_) {
        if (mounted) {
          setState(() => _status += ' Progress receipt unavailable.');
        }
      }
    }
  }

  Future<String> _enroll(PasskeyCancellation signal) async {
    await _store!.enroll(_passkeys, cancellation: signal);
    return 'Passkey created. Both PRFs matched; the encrypted marker is saved. '
        'Quit and reopen, then select Unlock saved test.';
  }

  Future<String> _unlock(PasskeyCancellation signal) async {
    await _store!.unlock(_passkeys, cancellation: signal);
    return 'Success: the saved marker decrypted. '
        'This passkey recovered the original encryption secret.';
  }

  @override
  void dispose() {
    _active?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final ready = _store != null && _active == null;
    final saved = _store?.exists ?? false;
    return Scaffold(
      appBar: AppBar(title: const Text('Keypass Provider Demo')),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 620),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(
                    'Passkey encryption test',
                    style: Theme.of(context).textTheme.headlineSmall,
                  ),
                  const SizedBox(height: 12),
                  const Text(
                    'Create a passkey and encrypt a test marker. '
                    'Reopen this app and unlock it to check that the provider '
                    'returns the same encryption material.',
                  ),
                  const SizedBox(height: 16),
                  Text(domain),
                  const SizedBox(height: 24),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(20),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          if (_stage != null) ...[
                            Text(
                              _stage!,
                              style: const TextStyle(
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            const SizedBox(height: 8),
                          ],
                          Text(_status),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  FilledButton(
                    onPressed: ready && !saved
                        ? () => _run('enroll', _enroll)
                        : null,
                    child: const Text('Create test passkey'),
                  ),
                  const SizedBox(height: 8),
                  FilledButton.tonal(
                    onPressed: ready && saved
                        ? () => _run('unlock', _unlock)
                        : null,
                    child: const Text('Unlock saved test'),
                  ),
                  const SizedBox(height: 8),
                  OutlinedButton(
                    onPressed: ready ? () => _run('check', _check) : null,
                    child: const Text('Check connection'),
                  ),
                  TextButton(
                    onPressed: _active == null ? null : () => _active?.cancel(),
                    child: const Text('Cancel'),
                  ),
                  if (Platform.isIOS || Platform.isAndroid)
                    OutlinedButton(
                      onPressed: ready
                          ? () => Navigator.of(context).push(
                              MaterialPageRoute<void>(
                                builder: (_) => const HardwarePage(),
                              ),
                            )
                          : null,
                      child: Text(
                        Platform.isAndroid
                            ? 'Test a hardware key (USB / NFC)'
                            : 'Test a hardware key over NFC',
                      ),
                    ),
                  const SizedBox(height: 24),
                  Text(
                    saved
                        ? 'Encrypted test saved on this device.'
                        : 'No encrypted test saved on this device.',
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Disposable test data only. '
                    'No Keybay vault is opened or changed.',
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
