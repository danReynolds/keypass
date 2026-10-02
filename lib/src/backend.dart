import 'dart:typed_data';

import 'cancellation.dart';
import 'models.dart';

/// Trusted native integration. All ceremony verification happens here, before
/// returning a binding or secret. Implementations must follow the backend
/// contract, including challenge, RP/origin, credential, signature and UV checks.
abstract interface class PasskeyBackend {
  /// Must not display UI or enumerate a user's credentials.
  Future<PasskeyAvailability> availability();

  /// Create a discoverable credential requiring UV; validate registration and
  /// PRF support. Each userId is a fresh local opaque handle, not an account ID.
  Future<PasskeyBinding> register(
    PasskeyRegistrationRequest request,
    PasskeyCancellation cancellation,
  );

  /// Return only a verified, UV-protected assertion for one allowed binding.
  /// Per-credential inputs must map to the selected credential exactly.
  Future<PasskeyAssertion> evaluate(
    PasskeyEvaluationRequest request,
    PasskeyCancellation cancellation,
  );

  Future<void> dispose();
}

final class PasskeyRegistrationRequest {
  PasskeyRegistrationRequest({
    required this.domain,
    required this.displayName,
    required this.label,
    required Uint8List userId,
    required Uint8List challenge,
    required Uint8List input,
  }) : userId = Uint8List.fromList(userId).asUnmodifiableView(),
       challenge = Uint8List.fromList(challenge).asUnmodifiableView(),
       input = Uint8List.fromList(input).asUnmodifiableView();

  final String domain;
  final String displayName;
  final String label;
  final Uint8List userId;
  final Uint8List challenge;
  final Uint8List input;
}

final class PasskeyEvaluationRequest {
  PasskeyEvaluationRequest({
    required List<PasskeyBinding> bindings,
    required Uint8List challenge,
  }) : bindings = List.unmodifiable(bindings),
       challenge = Uint8List.fromList(challenge).asUnmodifiableView();

  final List<PasskeyBinding> bindings;
  final Uint8List challenge;
}

/// Transfers exclusive ownership of [secret] to the core. It must be a writable
/// 32-byte buffer. The backend clears its own/native copies before completion,
/// and must not retain or use this buffer afterward, including on cancellation.
final class PasskeyAssertion {
  PasskeyAssertion({
    required Uint8List credentialId,
    required this.secret,
    required this.state,
  }) : credentialId = Uint8List.fromList(credentialId).asUnmodifiableView();

  final Uint8List credentialId;
  final Uint8List secret;
  final AuthenticatorState state;

  void clear() => secret.fillRange(0, secret.length, 0);

  @override
  String toString() => 'PasskeyAssertion(redacted)';
}

/// Deliberately unavailable until a qualified native adapter is connected.
final class UnavailablePasskeyBackend implements PasskeyBackend {
  const UnavailablePasskeyBackend();

  @override
  Future<PasskeyAvailability> availability() async =>
      const PasskeyAvailability.unavailable(
        PasskeyErrorCode.backendUnavailable,
      );

  @override
  Future<PasskeyBinding> register(
    PasskeyRegistrationRequest request,
    PasskeyCancellation cancellation,
  ) async => throw const PasskeyException(PasskeyErrorCode.backendUnavailable);

  @override
  Future<PasskeyAssertion> evaluate(
    PasskeyEvaluationRequest request,
    PasskeyCancellation cancellation,
  ) async => throw const PasskeyException(PasskeyErrorCode.backendUnavailable);

  @override
  Future<void> dispose() async {}
}
