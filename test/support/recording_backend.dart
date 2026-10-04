import 'dart:async';
import 'dart:typed_data';

import 'package:keypass/keypass_backend.dart';

/// Synthetic adapter for lifecycle testing. No cryptographic claims.
final class RecordingBackend implements PasskeyBackend {
  PasskeyAvailability readiness = const PasskeyAvailability.ready(
    supportsMultipleBindings: true,
  );
  final registrations = <PasskeyRegistrationRequest>[];
  final evaluations = <PasskeyEvaluationRequest>[];
  final buffers = <Uint8List>[];
  int disposed = 0;
  Future<void> Function()? onDispose;
  int availabilityCalls = 0;
  Future<PasskeyAvailability> Function()? onAvailability;
  Future<PasskeyBinding> Function(PasskeyRegistrationRequest)? onRegister;
  Future<PasskeyAssertion> Function(
    PasskeyEvaluationRequest,
    PasskeyCancellation,
  )?
  onEvaluate;

  @override
  Future<PasskeyAvailability> availability({
    PasskeyCancellation? cancellation,
  }) async {
    availabilityCalls++;
    return onAvailability == null ? readiness : await onAvailability!();
  }

  @override
  Future<PasskeyBinding> register(
    PasskeyRegistrationRequest request,
    PasskeyCancellation cancellation,
  ) async {
    registrations.add(request);
    if (onRegister != null) return await onRegister!(request);
    return binding(input: request.input, userId: request.userId);
  }

  @override
  Future<PasskeyAssertion> evaluate(
    PasskeyEvaluationRequest request,
    PasskeyCancellation cancellation,
  ) async {
    evaluations.add(request);
    if (onEvaluate != null) return await onEvaluate!(request, cancellation);
    return assertion(request.bindings.first);
  }

  PasskeyAssertion assertion(
    PasskeyBinding binding, {
    int byte = 7,
    int length = 32,
  }) {
    final secret = Uint8List(length)..fillRange(0, length, byte);
    buffers.add(secret);
    return PasskeyAssertion(
      credentialId: binding.credentialId,
      secret: secret,
      state: binding.authenticatorState,
    );
  }

  @override
  Future<void> dispose() async {
    disposed++;
    await onDispose?.call();
  }
}

PasskeyBinding binding({
  int id = 1,
  String domain = 'vault.example.com',
  Uint8List? input,
  Uint8List? userId,
}) => PasskeyBinding(
  authenticatorState: AuthenticatorState(
    backupEligible: true,
    backupState: true,
    signCount: 0,
  ),
  domain: domain,
  credentialId: Uint8List.fromList([id]),
  userId: userId ?? Uint8List(32),
  // Intentionally not a valid COSE key: these tests do not verify ceremonies.
  publicKeyCose: Uint8List.fromList([0xa0]),
  input: input ?? Uint8List.fromList([id]),
);
