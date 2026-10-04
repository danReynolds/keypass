import 'dart:convert';
import 'dart:typed_data';

import '../backend.dart';
import '../cancellation.dart';
import '../models.dart';
import '../webauthn/verifier.dart';

/// The only secret-bearing transport field is a mutable binary buffer.
final class NativeReply {
  NativeReply(this.metadata, [Uint8List? secret])
    : secret = secret ?? Uint8List(0);
  final Map<String, Object?> metadata;
  final Uint8List secret;
  void clear() => secret.fillRange(0, secret.length, 0);
}

abstract interface class NativeTransport {
  Future<NativeReply> exchange(
    Map<String, Object?> request,
    PasskeyCancellation cancellation,
  );
  Future<void> dispose();
}

/// Shared verification for all OS adapters. Native code presents provider UI
/// and returns raw evidence; it cannot bypass Dart's ceremony verification.
final class NativePasskeyBackend implements PasskeyBackend {
  NativePasskeyBackend(this.transport, {required this.domain});
  final NativeTransport transport;
  final String domain;
  String? _origin;
  bool _android = false;

  @override
  Future<PasskeyAvailability> availability({
    PasskeyCancellation? cancellation,
  }) async {
    try {
      final reply = await transport.exchange({
        'operation': 'availability',
        'domain': domain,
      }, cancellation ?? PasskeyCancellation());
      try {
        final origin = reply.metadata['origin'];
        final platform = reply.metadata['platform'];
        if (origin is! String ||
            !['apple', 'android', 'windows'].contains(platform)) {
          throw const PasskeyException(PasskeyErrorCode.backendFailure);
        }
        _android = platform == 'android';
        WebAuthnVerifier(
          domain: domain,
          origin: origin,
          androidAppOrigin: _android,
        );
        _origin = origin;
        return PasskeyAvailability.ready(
          supportsMultipleBindings: reply.metadata['multiple'] == true,
        );
      } finally {
        reply.clear();
      }
    } on PasskeyException catch (e) {
      return PasskeyAvailability.unavailable(e.code);
    }
  }

  WebAuthnVerifier get _verifier {
    final origin = _origin;
    if (origin == null) {
      throw const PasskeyException(PasskeyErrorCode.hostUnavailable);
    }
    return WebAuthnVerifier(
      domain: domain,
      origin: origin,
      androidAppOrigin: _android,
    );
  }

  @override
  Future<PasskeyBinding> register(
    PasskeyRegistrationRequest request,
    PasskeyCancellation cancellation,
  ) async {
    final reply = await transport.exchange({
      'operation': 'register',
      'publicKey': {
        'rp': {'id': request.domain, 'name': request.displayName},
        'user': {
          'id': encode(request.userId),
          'name': request.label,
          'displayName': request.label,
        },
        'challenge': encode(request.challenge),
        'pubKeyCredParams': [
          {'type': 'public-key', 'alg': -7},
        ],
        'authenticatorSelection': {
          'residentKey': 'required',
          'requireResidentKey': true,
          'userVerification': 'required',
        },
        'attestation': 'none',
        'timeout': 120000,
        'extensions': {'prf': <String, Object?>{}},
      },
    }, cancellation);
    try {
      final verified = _verifier.registration(
        challenge: request.challenge,
        credentialId: bytes(reply.metadata, 'credentialId', 1024),
        clientDataJSON: bytes(reply.metadata, 'clientDataJSON', 8192),
        attestationObject: bytes(reply.metadata, 'attestationObject', 16384),
        prfEnabled: reply.metadata['prfEnabled'] == true,
      );
      return PasskeyBinding(
        domain: request.domain,
        credentialId: verified.credentialId,
        userId: request.userId,
        publicKeyCose: verified.publicKeyCose,
        input: request.input,
        authenticatorState: verified.state,
      );
    } finally {
      reply.clear();
    }
  }

  @override
  Future<PasskeyAssertion> evaluate(
    PasskeyEvaluationRequest request,
    PasskeyCancellation cancellation,
  ) async {
    final reply = await transport.exchange({
      'operation': 'evaluate',
      'publicKey': {
        'rpId': domain,
        'challenge': encode(request.challenge),
        'allowCredentials': [
          for (final b in request.bindings)
            {'type': 'public-key', 'id': encode(b.credentialId)},
        ],
        'userVerification': 'required',
        'timeout': 120000,
        'extensions': {
          'prf': {
            'evalByCredential': {
              for (final b in request.bindings)
                encode(b.credentialId): {'first': encode(b.input)},
            },
          },
        },
      },
    }, cancellation);
    var transferred = false;
    try {
      final id = bytes(reply.metadata, 'credentialId', 1024);
      final matches = request.bindings.where(
        (b) => encode(b.credentialId) == encode(id),
      );
      if (matches.length != 1) {
        throw const PasskeyException(PasskeyErrorCode.verificationFailed);
      }
      final binding = matches.single;
      final state = _verifier.assertion(
        challenge: request.challenge,
        credentialId: id,
        expectedCredentialId: binding.credentialId,
        expectedUserId: binding.userId,
        userHandle: reply.metadata['userHandle'] == null
            ? null
            : bytes(reply.metadata, 'userHandle', 64),
        publicKeyCose: binding.publicKeyCose,
        clientDataJSON: bytes(reply.metadata, 'clientDataJSON', 8192),
        authenticatorData: bytes(reply.metadata, 'authenticatorData', 8192),
        signature: bytes(reply.metadata, 'signature', 72),
        previousState: binding.authenticatorState,
      );
      if (reply.secret.length != 32) {
        throw const PasskeyException(PasskeyErrorCode.prfUnavailable);
      }
      final assertion = PasskeyAssertion(
        credentialId: id,
        secret: reply.secret,
        state: state,
      );
      transferred = true;
      return assertion;
    } finally {
      if (!transferred) reply.clear();
    }
  }

  @override
  Future<void> dispose() => transport.dispose();
}

String encode(List<int> value) => base64Url.encode(value).replaceAll('=', '');
Uint8List bytes(Map<String, Object?> metadata, String field, int maximum) {
  final value = metadata[field];
  if (value is! String ||
      value.isEmpty ||
      value.length > ((maximum + 2) ~/ 3) * 4 ||
      !RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(value)) {
    throw const PasskeyException(PasskeyErrorCode.verificationFailed);
  }
  try {
    final decoded = base64Url.decode(base64Url.normalize(value));
    if (decoded.length > maximum || encode(decoded) != value) {
      throw const PasskeyException(PasskeyErrorCode.verificationFailed);
    }
    return decoded;
  } on FormatException {
    throw const PasskeyException(PasskeyErrorCode.verificationFailed);
  }
}
