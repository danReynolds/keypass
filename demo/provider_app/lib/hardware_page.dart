import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:keypass/keypass.dart';
import 'package:path_provider/path_provider.dart';
import 'store.dart';

const hardwareNamespace = 'dev.keypass.hardware-demo';

/// Disposable hardware qualification, separate from the provider fixture.
class HardwarePage extends StatefulWidget {
  const HardwarePage({super.key});
  @override
  State<HardwarePage> createState() => _HardwarePageState();
}

class _HardwarePageState extends State<HardwarePage> {
  // The client is lightweight; each operation owns its connection selection.
  late final _passkeys = Keypass.hardware(
    rpId: hardwareNamespace,
    displayName: 'Keypass Hardware Demo',
    requestPin: _requestPin,
    selectConnection: _selectConnection,
    onEvent: _onEvent,
  );

  Future<HardwareConnection?> _selectConnection(
    List<HardwareConnection> connections,
    PasskeyCancellation cancellation,
  ) async {
    if (!mounted || cancellation.isCancelled) return null;
    return showDialog<HardwareConnection>(
      context: context,
      barrierDismissible: false,
      builder: (_) => _ConnectionDialog(
        connections: connections,
        cancellation: cancellation,
      ),
    );
  }

  final _started = DateTime.now().toUtc().toIso8601String();
  DemoStore? _store;
  File? _import;
  File? _receipt;
  Future<void> _receiptWrites = Future.value();
  PasskeyCancellation? _active;
  String _status = 'Opening the hardware test…';
  String _operation = 'startup';
  String? _code;
  int _scans = 0;
  int _pins = 0;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _initialize());
  }

  Future<void> _initialize() async {
    try {
      final support = await getApplicationSupportDirectory();
      final documents = await getApplicationDocumentsDirectory();
      final directory = Directory(
        '${support.path}/hardware-test/$hardwareNamespace',
      );
      await directory.create(recursive: true);
      _store = DemoStore(File('${directory.path}/encrypted-test.json'));
      _receipt = File('${directory.path}/receipt.json');
      _import = File('${documents.path}/hardware-import.json');
      if (mounted) await _run('check', _check);
    } catch (_) {
      if (mounted) {
        setState(() => _status = 'Could not open the hardware test storage.');
      }
    }
  }

  Future<Uint8List?> _requestPin(
    HardwarePinRequest request,
    PasskeyCancellation cancellation,
  ) async {
    if (!mounted || cancellation.isCancelled) return null;
    setState(() {
      _pins++;
      _status = _scans > 0
          ? 'Remove the key, enter its FIDO2 PIN, then scan it again.'
          : 'Enter the connected security key’s FIDO2 PIN.';
    });
    await _writeReceipt();
    if (!mounted || cancellation.isCancelled) return null;
    return showDialog<Uint8List>(
      context: context,
      barrierDismissible: false,
      builder: (_) => _PinDialog(request: request, cancellation: cancellation),
    );
  }

  void _onEvent(HardwareEvent event) {
    if (!mounted) return;
    setState(() {
      if (event == HardwareEvent.presentKey) {
        _scans++;
        _status = Platform.isAndroid
            ? 'Hold the security key against the back of the phone. Keep it still until the app advances.'
            : 'Hold the security key near the top of the iPhone. Keep it there until the NFC sheet closes.';
      } else {
        _status = 'Touch the security key to approve.';
      }
    });
    unawaited(_writeReceipt().catchError((Object _) {}));
  }

  Future<void> _writeReceipt() {
    final file = _receipt;
    if (file == null) return Future.value();
    // Public progress only. No PIN, binding, authenticator response or PRF.
    final json = jsonEncode({
      'platform': Platform.operatingSystem,
      'pid': pid,
      'started': _started,
      'client': 'Keypass.hardware',
      'route': 'hardware',
      'transport': _scans > 0
          ? 'NFC'
          : (_operation == 'unlock' || _operation == 'enroll')
          ? 'USB'
          : null,
      'namespace': hardwareNamespace,
      'operation': _operation,
      'busy': _active != null,
      'saved': _store?.exists ?? false,
      'status': _status,
      'code': _code,
      'scans': _scans,
      'pinPrompts': _pins,
    });
    return _receiptWrites = _receiptWrites.catchError((Object _) {}).then((
      _,
    ) async {
      final pending = File('${file.path}.pending');
      await pending.writeAsString(json, flush: true);
      await pending.rename(file.path);
    });
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
      _code = null;
      _scans = 0;
      _pins = 0;
      _status = operation == 'check'
          ? 'Checking the hardware host…'
          : 'Preparing the hardware test…';
    });
    try {
      await _writeReceipt();
      final status = await action(signal);
      if (mounted) setState(() => _status = status);
    } on PasskeyException catch (error) {
      if (mounted) {
        setState(() {
          _code = error.code.name;
          _status =
              'Operation stopped: ${error.code.name}. No automatic PIN retry was attempted.';
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          _code = 'demoFailure';
          _status = 'The hardware test could not complete.';
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

  Future<String> _check(PasskeyCancellation _) async {
    final result = await _passkeys.check();
    if (!result.canAttempt) throw PasskeyException(result.reason!);
    return 'Hardware host ready. Import the Mac test, then unlock it with the same key. '
        'Key capabilities are checked during the operation.';
  }

  Future<String> _importTest(PasskeyCancellation _) async {
    await _store!.importHardware(_import!, namespace: hardwareNamespace);
    return 'Mac ciphertext imported. Unlock it with the physical key to verify the same credential '
        'recovers the encryption secret.';
  }

  Future<String> _unlock(PasskeyCancellation signal) async {
    await _store!.unlock(_passkeys, cancellation: signal);
    return 'Success: the saved marker decrypted via ${_scans > 0 ? "NFC" : "USB"} with the original encryption secret.';
  }

  Future<String> _enroll(PasskeyCancellation signal) async {
    await _store!.enroll(_passkeys, cancellation: signal);
    return 'Hardware credential created. Two PRFs matched and the encrypted marker was saved. '
        'Reopen the app and unlock to test recovery.';
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
    final staged = _import?.existsSync() ?? false;
    return PopScope(
      canPop: _active == null,
      child: Scaffold(
        appBar: AppBar(
          title: Text(
            Platform.isAndroid
                ? 'Hardware key · USB / NFC'
                : 'Hardware key · NFC',
          ),
        ),
        body: SafeArea(
          child: ListView(
            padding: const EdgeInsets.all(24),
            children: [
              Text(
                'Use the same physical key',
                style: Theme.of(context).textTheme.headlineSmall,
              ),
              const SizedBox(height: 12),
              Text(
                Platform.isAndroid
                    ? 'Unlock the Mac test using the same key. For NFC, hold the key against the back of the phone until the PIN prompt appears. Remove it, enter its FIDO2 PIN, then scan again. For USB, connect the key and choose it when asked.'
                    : 'Unlock the encrypted test created on the Mac. For a PIN-based key: scan once, enter its FIDO2 PIN in this app, then scan again. Keep the key at the top of the phone until each NFC sheet closes.',
              ),

              const SizedBox(height: 20),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(20),
                  child: Text(_status),
                ),
              ),
              const SizedBox(height: 16),
              FilledButton(
                onPressed: ready && saved
                    ? () => _run('unlock', _unlock)
                    : null,
                child: const Text('Unlock saved hardware test'),
              ),
              OutlinedButton(
                onPressed: ready && !saved && staged
                    ? () => _run('import', _importTest)
                    : null,
                child: const Text('Import Mac encrypted test'),
              ),
              OutlinedButton(
                onPressed: ready ? () => _run('check', _check) : null,
                child: const Text('Check hardware host'),
              ),
              TextButton(
                onPressed: _active == null ? null : () => _active?.cancel(),
                child: const Text('Cancel'),
              ),
              const SizedBox(height: 16),
              Text(
                saved
                    ? 'Hardware test saved on this phone.'
                    : 'No hardware test saved on this phone.',
              ),
              const SizedBox(height: 8),
              const Text(
                'Disposable encrypted marker only. The provider test and Keybay vaults are separate.',
              ),
              const SizedBox(height: 24),
              TextButton(
                onPressed: ready && !saved && !staged
                    ? () => _run('enroll', _enroll)
                    : null,
                child: const Text('Create a new hardware test'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _PinDialog extends StatefulWidget {
  const _PinDialog({required this.request, required this.cancellation});
  final HardwarePinRequest request;
  final PasskeyCancellation cancellation;
  @override
  State<_PinDialog> createState() => _PinDialogState();
}

class _PinDialogState extends State<_PinDialog> {
  final _controller = TextEditingController();
  StreamSubscription<void>? _subscription;
  String? _error;
  bool _closed = false;
  @override
  void initState() {
    super.initState();
    _subscription = widget.cancellation.onCancel.listen((_) => _finish(null));
    if (widget.cancellation.isCancelled) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _finish(null));
    }
  }

  void _finish(Uint8List? value) {
    if (_closed || !mounted) {
      value?.fillRange(0, value.length, 0);
      return;
    }
    _closed = true;
    _controller.clear();
    Navigator.of(context).pop(value);
  }

  void _submit() {
    if (widget.cancellation.isCancelled) {
      _finish(null);
      return;
    }
    final value = Uint8List.fromList(utf8.encode(_controller.text));
    if (value.length < 4 || value.length > 63 || value.contains(0)) {
      value.fillRange(0, value.length, 0);
      setState(
        () => _error = 'Enter the existing FIDO2 PIN (4–63 UTF-8 bytes).',
      );
      return;
    }
    _finish(value);
  }

  @override
  void dispose() {
    unawaited(_subscription?.cancel());
    _controller.clear();
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('Security key PIN'),
    content: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          'Type the key’s existing FIDO2 PIN. Tapping its button does not enter the PIN. '
          '${widget.request.attemptsRemaining} attempts remain.',
        ),
        const SizedBox(height: 16),
        TextField(
          controller: _controller,
          autofocus: true,
          obscureText: true,
          autocorrect: false,
          enableSuggestions: false,
          enableIMEPersonalizedLearning: false,
          keyboardType: TextInputType.visiblePassword,
          decoration: InputDecoration(
            labelText: 'FIDO2 PIN',
            errorText: _error,
          ),
          onSubmitted: (_) => _submit(),
        ),
      ],
    ),
    actions: [
      TextButton(onPressed: () => _finish(null), child: const Text('Cancel')),
      FilledButton(onPressed: _submit, child: const Text('Continue')),
    ],
  );
}

class _ConnectionDialog extends StatefulWidget {
  const _ConnectionDialog({
    required this.connections,
    required this.cancellation,
  });
  final List<HardwareConnection> connections;
  final PasskeyCancellation cancellation;
  @override
  State<_ConnectionDialog> createState() => _ConnectionDialogState();
}

class _ConnectionDialogState extends State<_ConnectionDialog> {
  StreamSubscription<void>? _subscription;
  bool _closed = false;
  @override
  void initState() {
    super.initState();
    _subscription = widget.cancellation.onCancel.listen((_) => _finish(null));
    if (widget.cancellation.isCancelled) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _finish(null));
    }
  }

  void _finish(HardwareConnection? connection) {
    if (_closed || !mounted) return;
    _closed = true;
    Navigator.of(context).pop(connection);
  }

  @override
  void dispose() {
    unawaited(_subscription?.cancel());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => SimpleDialog(
    title: const Text('Choose a connection'),
    children: [
      for (final connection in widget.connections)
        SimpleDialogOption(
          onPressed: () => _finish(connection),
          child: Text(connection.name),
        ),
      SimpleDialogOption(
        onPressed: () => _finish(null),
        child: const Text('Cancel'),
      ),
    ],
  );
}
