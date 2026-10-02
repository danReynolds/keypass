import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/digests/sha256.dart';
import 'backend.dart';
import 'cancellation.dart';
import 'hardware/interaction.dart';
import 'models.dart';
import 'native/default_stub.dart'
    if (dart.library.io) 'native/default_backend.dart';

part 'record.dart';
part 'result.dart';

/// Immutable configuration for verified passkey-derived encryption material.
/// Construction accesses no provider or device. Each call owns its backend;
/// this client needs no disposal.
abstract interface class Keypass {
  /// Use the OS passkey provider and UI. Requires consumer app/domain setup.
  factory Keypass.system({required String rpId, String? displayName}) {
    final scope = validateDomain(rpId, PasskeyErrorCode.invalidRequest);
    return _Keypass(
      rpId: scope,
      displayName: displayName,
      route: PasskeyRoute.system,
      createBackend: () => defaultBackend(scope),
    );
  }

  /// Direct physical FIDO2 access, without a Keypass-operated service.
  /// RP ID scopes credentials; it does not authenticate the local executable.
  /// Handlers are configuration, never cached PINs or selected connections.
  factory Keypass.hardware({
    required String rpId,
    String? displayName,
    HardwarePinPrompt? requestPin,
    HardwareConnectionPicker? selectConnection,
    void Function(HardwareEvent)? onEvent,
  }) {
    final scope = validateDomain(rpId, PasskeyErrorCode.invalidRequest);
    final interaction = HardwareInteraction(
      requestPin: requestPin,
      selectConnection: selectConnection,
      onEvent: onEvent,
    );
    return _Keypass(
      rpId: scope,
      displayName: displayName,
      route: PasskeyRoute.hardware,
      createBackend: () => hardwareBackend(scope, interaction),
    );
  }

  /// Optional, prompt-free readiness to attempt access; not proof of PRF support.
  /// Does not reserve access. An overlapping operation can fail with busy.
  Future<PasskeyReadiness> check();

  /// Create a credential and verify two matching secret evaluations.
  /// Generates the user handle, challenges and original PRF input.
  /// Failure after registration can leave a credential in the provider.
  /// Dispose the returned result in finally, including on persistence failure.
  /// Do not abandon the Future or use Future.timeout as cancellation: cancel
  /// the token and await settlement, disposing any successful result.
  Future<PasskeyResult> create({
    required String label,
    PasskeyCancellation? cancellation,
  });

  /// Recover exactly this record's secret, with no enrollment or fallback.
  /// Rejects RP/route mismatches before any backend or UI is accessed.
  /// Persist the returned record's updated verification state transactionally.
  /// Do not abandon the Future or use Future.timeout as cancellation: cancel
  /// the token and await settlement, disposing any successful result.
  Future<PasskeyResult> unlock(
    PasskeyRecord record, {
    PasskeyCancellation? cancellation,
  });
}

/// Adapter integration only: return a FRESH operation-owned backend each time.
Keypass keypassWithBackendFactory({
  required PasskeyBackend Function() createBackend,
  required String rpId,
  String? displayName,
  PasskeyRoute route = PasskeyRoute.system,
}) => _Keypass(
  rpId: validateDomain(rpId, PasskeyErrorCode.invalidRequest),
  displayName: displayName,
  route: route,
  createBackend: createBackend,
);

/// Trusted adapter/test conversions; not exported by the consumer library.
PasskeyRecord recordFromBinding(PasskeyBinding binding) =>
    PasskeyRecord._(binding);
PasskeyBinding bindingFromRecord(PasskeyRecord record) => record._binding;

final class _Keypass implements Keypass {
  _Keypass({
    required this.rpId,
    required this.route,
    required this.createBackend,
    String? displayName,
  }) : displayName = displayName ?? rpId {
    if (this.displayName.trim().isEmpty || this.displayName.length > 256) {
      throw const PasskeyException(PasskeyErrorCode.invalidRequest);
    }
  }
  final String rpId;
  final String displayName;
  final PasskeyRoute route;
  final PasskeyBackend Function() createBackend;

  // One operation per isolate across facade instances. Native gates also
  // protect process-wide slots across isolates. Returned results hold no gate.
  static bool _busy = false;

  @override
  Future<PasskeyReadiness> check() => _run(null, (backend, signal) async {
    final available = await _native(backend.availability);
    return PasskeyReadiness._(available.reason);
  });

  @override
  Future<PasskeyResult> create({
    required String label,
    PasskeyCancellation? cancellation,
  }) {
    if (label.trim().isEmpty || label.length > 256) {
      return Future.error(
        const PasskeyException(PasskeyErrorCode.invalidRequest),
      );
    }
    return _run(cancellation, (backend, signal) async {
      await _ready(backend, signal);
      final request = PasskeyRegistrationRequest(
        domain: rpId,
        displayName: displayName,
        label: label,
        userId: _randomBytes(),
        challenge: _randomBytes(),
        input: _randomBytes(),
      );
      var binding = await _native(() => backend.register(request, signal));
      _checkCancellation(signal);
      if (binding.route != route ||
          binding.domain != rpId ||
          !_equal(binding.input, request.input) ||
          !_equal(binding.userId, request.userId)) {
        throw const PasskeyException(PasskeyErrorCode.verificationFailed);
      }
      final first = await _evaluate(backend, binding, signal);
      var transferred = false;
      try {
        binding = binding.withState(first.state);
        final second = await _evaluate(backend, binding, signal);
        try {
          if (!_equal(first.secret, second.secret)) {
            throw const PasskeyException(PasskeyErrorCode.inconsistentSecret);
          }
          final result = PasskeyResult._(
            PasskeyRecord._(binding.withState(second.state)),
            first.secret,
          );
          transferred = true;
          return result;
        } finally {
          second.clear();
        }
      } finally {
        if (!transferred) first.clear();
      }
    });
  }

  @override
  Future<PasskeyResult> unlock(
    PasskeyRecord record, {
    PasskeyCancellation? cancellation,
  }) {
    if (record.rpId != rpId || record.route != route) {
      return Future.error(
        const PasskeyException(PasskeyErrorCode.invalidBinding),
      );
    }
    return _run(cancellation, (backend, signal) async {
      await _ready(backend, signal);
      final assertion = await _evaluate(backend, record._binding, signal);
      try {
        return PasskeyResult._(
          PasskeyRecord._(record._binding.withState(assertion.state)),
          assertion.secret,
        );
      } catch (_) {
        assertion.clear();
        rethrow;
      }
    });
  }

  Future<T> _run<T>(
    PasskeyCancellation? external,
    Future<T> Function(PasskeyBackend, PasskeyCancellation) action,
  ) async {
    if (external?.isCancelled ?? false) {
      throw const PasskeyException(PasskeyErrorCode.cancelled);
    }
    if (_busy) throw const PasskeyException(PasskeyErrorCode.busy);
    _busy = true;
    final signal = PasskeyCancellation();
    var subscription = external?.onCancel.listen((_) => signal.cancel());
    PasskeyBackend? backend;
    T? output;
    var transferred = false;
    try {
      backend = createBackend();
      final value = await action(backend, signal);
      output = value;
      final finished = backend;
      backend = null; // Dispose exactly once, including disposal failure.
      await _native(finished.dispose);
      await subscription?.cancel();
      subscription = null;
      _checkCancellation(signal);
      if (external?.isCancelled ?? false) {
        throw const PasskeyException(PasskeyErrorCode.cancelled);
      }
      transferred = true;
      return value;
    } on PasskeyException {
      rethrow;
    } catch (_) {
      throw const PasskeyException(PasskeyErrorCode.backendFailure);
    } finally {
      if (transferred) {
        // No await after the final cancellation check and ownership transfer.
        signal.cancel();
        _busy = false;
      } else {
        try {
          signal.cancel();
          if (backend != null) await _native(backend.dispose);
        } finally {
          try {
            await subscription?.cancel();
          } finally {
            if (output is PasskeyResult) output.dispose();
            _busy = false;
          }
        }
      }
    }
  }

  @override
  String toString() => 'Keypass(${route.name})';
}

Future<void> _ready(PasskeyBackend backend, PasskeyCancellation signal) async {
  _checkCancellation(signal);
  final available = await _native(backend.availability);
  _checkCancellation(signal);
  if (!available.canAttempt) throw PasskeyException(available.reason!);
}

Future<PasskeyAssertion> _evaluate(
  PasskeyBackend backend,
  PasskeyBinding binding,
  PasskeyCancellation signal,
) async {
  _checkCancellation(signal);
  final assertion = await _native(
    () => backend.evaluate(
      PasskeyEvaluationRequest(bindings: [binding], challenge: _randomBytes()),
      signal,
    ),
  );
  try {
    _checkCancellation(signal);
    if (assertion.secret.length != 32 ||
        !_equal(binding.credentialId, assertion.credentialId)) {
      throw const PasskeyException(PasskeyErrorCode.verificationFailed);
    }
    // Enforce the trusted backend's writable, exclusive buffer contract.
    assertion.secret[0] = assertion.secret[0];
    return assertion;
  } catch (_) {
    try {
      assertion.clear();
    } on UnsupportedError {
      /* Invalid backend buffer. */
    }
    rethrow;
  }
}

Future<T> _native<T>(Future<T> Function() action) async {
  try {
    return await action();
  } on PasskeyException {
    rethrow;
  } catch (_) {
    throw const PasskeyException(PasskeyErrorCode.backendFailure);
  }
}

void _checkCancellation(PasskeyCancellation signal) {
  if (signal.isCancelled) {
    throw const PasskeyException(PasskeyErrorCode.cancelled);
  }
}

Uint8List _randomBytes() {
  final random = Random.secure();
  return Uint8List.fromList(List.generate(32, (_) => random.nextInt(256)));
}

bool _equal(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var difference = 0;
  for (var i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  // No early exit. Dart does not guarantee constant-time execution.
  return difference == 0;
}
