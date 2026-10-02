import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/digests/sha256.dart';
import '../backend.dart';
import '../cancellation.dart';
import '../models.dart';
import '../native/backend.dart';
import '../webauthn/verifier.dart';
import 'interaction.dart';

/// WebAuthn's PRF input normalization, applied exactly once before direct CTAP.
Uint8List hardwarePrfSalt(Uint8List input) => SHA256Digest().process(
  Uint8List.fromList([...utf8.encode('WebAuthn PRF'), 0, ...input]),
);

/// Fresh local ceremony. This is not a browser origin or executable identity.
Uint8List hardwareClientHash(
  String namespace,
  Uint8List challenge, {
  required bool registration,
}) {
  if (challenge.length != 32) {
    throw const PasskeyException(PasskeyErrorCode.invalidRequest);
  }
  return SHA256Digest().process(
    Uint8List.fromList([
      ...utf8.encode('Keypass direct CTAP v1'),
      0,
      registration ? 1 : 2,
      ...utf8.encode(namespace),
      0,
      ...challenge,
    ]),
  );
}

final class HardwarePasskeyBackend implements PasskeyBackend {
  HardwarePasskeyBackend(
    this.transport, {
    required this.namespace,
    this.interaction = const HardwareInteraction(),
  });
  final NativeTransport transport;
  final String namespace;
  final HardwareInteraction interaction;
  // Selected for one operation backend; never retained by the facade.
  String? _selected;

  Future<List<Map<String, Object?>>> _devices(
    PasskeyCancellation cancellation,
  ) async {
    final reply = await transport.exchange({
      'operation': 'discover',
    }, cancellation);
    try {
      final devices = reply.metadata['devices'];
      if (reply.secret.isNotEmpty || devices is! List || devices.length > 16) {
        throw const PasskeyException(PasskeyErrorCode.backendFailure);
      }
      return devices
          .map((value) {
            if (value is! Map<String, dynamic> ||
                value['id'] is! String ||
                (value['id'] as String).length != 64 ||
                !RegExp(r'^[0-9a-f]{64}$').hasMatch(value['id'] as String) ||
                value['name'] is! String ||
                (value['name'] as String).length > 128) {
              throw const PasskeyException(PasskeyErrorCode.backendFailure);
            }
            return Map<String, Object?>.from(value);
          })
          .toList(growable: false);
    } finally {
      reply.clear();
    }
  }

  @override
  Future<PasskeyAvailability> availability() async {
    try {
      final devices = await _devices(PasskeyCancellation());
      return devices.isEmpty
          ? const PasskeyAvailability.unavailable(
              PasskeyErrorCode.deviceUnavailable,
            )
          : const PasskeyAvailability.ready();
    } on PasskeyException catch (e) {
      return PasskeyAvailability.unavailable(e.code);
    }
  }

  Future<String> _select(PasskeyCancellation cancellation) async {
    final devices = await _devices(cancellation);
    if (devices.isEmpty) {
      throw const PasskeyException(PasskeyErrorCode.deviceUnavailable);
    }
    if (_selected != null) {
      if (!devices.any((d) => d['id'] == _selected)) {
        throw const PasskeyException(PasskeyErrorCode.deviceUnavailable);
      }
      return _selected!;
    }
    int? index = 0;
    if (devices.length > 1) {
      final select = interaction.selectConnection;
      if (select == null) {
        throw const PasskeyException(PasskeyErrorCode.deviceSelectionRequired);
      }
      final signal = PasskeyCancellation();
      final aborted = Completer<HardwareConnection?>();
      void abort(PasskeyErrorCode code) {
        signal.cancel();
        if (!aborted.isCompleted) {
          aborted.completeError(PasskeyException(code));
        }
      }

      final subscription = cancellation.onCancel.listen(
        (_) => abort(PasskeyErrorCode.cancelled),
      );
      final deadline = Timer(
        const Duration(seconds: 120),
        () => abort(PasskeyErrorCode.timeout),
      );
      try {
        if (cancellation.isCancelled) {
          throw const PasskeyException(PasskeyErrorCode.cancelled);
        }
        final offered = List<HardwareConnection>.unmodifiable(
          devices.map(
            (d) => hardwareConnection(
              name: d['name']! as String,
              transport: switch (d['transport']) {
                'usb' => HardwareTransport.usb,
                'nfc' => HardwareTransport.nfc,
                _ => null,
              },
            ),
          ),
        );
        final selected = await Future.any<HardwareConnection?>([
          Future<HardwareConnection?>.sync(() => select(offered, signal)),
          aborted.future,
        ]);
        index = selected == null
            ? null
            : offered.indexWhere((c) => identical(c, selected));
      } finally {
        deadline.cancel();
        await subscription.cancel();
        signal.cancel();
      }
    }
    if (cancellation.isCancelled || index == null) {
      throw const PasskeyException(PasskeyErrorCode.cancelled);
    }
    if (index < 0 || index >= devices.length) {
      throw const PasskeyException(PasskeyErrorCode.invalidRequest);
    }
    return _selected = devices[index]['id']! as String;
  }

  @override
  Future<PasskeyBinding> register(
    PasskeyRegistrationRequest request,
    PasskeyCancellation cancellation,
  ) async {
    if (request.domain != namespace) {
      throw const PasskeyException(PasskeyErrorCode.invalidRequest);
    }
    final device = await _select(cancellation);
    final reply = await transport.exchange({
      'operation': 'register',
      'device': device,
      'namespace': namespace,
      'displayName': request.displayName,
      'label': request.label,
      'userId': encode(request.userId),
      'clientDataHash': encode(
        hardwareClientHash(namespace, request.challenge, registration: true),
      ),
    }, cancellation);
    try {
      if (reply.secret.isNotEmpty ||
          reply.metadata['attestationVerified'] != true) {
        throw const PasskeyException(PasskeyErrorCode.verificationFailed);
      }
      final verified = WebAuthnVerifier.hardware(domain: namespace)
          .hardwareRegistration(
            credentialId: bytes(reply.metadata, 'credentialId', 1024),
            authenticatorData: bytes(reply.metadata, 'authenticatorData', 8192),
          );
      final transports = reply.metadata['transports'];
      if (transports is! List || transports.any((v) => v is! String)) {
        throw const PasskeyException(PasskeyErrorCode.verificationFailed);
      }
      return PasskeyBinding(
        route: PasskeyRoute.hardware,
        domain: namespace,
        transports: transports.cast<String>(),
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
    // One explicit credential per ceremony keeps its salt and key unambiguous.
    if (request.bindings.length != 1) {
      throw const PasskeyException(PasskeyErrorCode.selectionUnsupported);
    }
    final binding = request.bindings.single;
    if (binding.route != PasskeyRoute.hardware || binding.domain != namespace) {
      throw const PasskeyException(PasskeyErrorCode.invalidBinding);
    }
    final device = await _select(cancellation);
    final hash = hardwareClientHash(
      namespace,
      request.challenge,
      registration: false,
    );
    final reply = await transport.exchange({
      'operation': 'evaluate',
      'device': device,
      'namespace': namespace,
      'clientDataHash': encode(hash),
      'credentialId': encode(binding.credentialId),
      'hmacSalt': encode(hardwarePrfSalt(binding.input)),
    }, cancellation);
    var transferred = false;
    try {
      final id = bytes(reply.metadata, 'credentialId', 1024);
      final state = WebAuthnVerifier.hardware(domain: namespace)
          .hardwareAssertion(
            clientDataHash: hash,
            credentialId: id,
            binding: binding,
            userHandle: reply.metadata['userHandle'] == null
                ? null
                : bytes(reply.metadata, 'userHandle', 64),
            authenticatorData: bytes(reply.metadata, 'authenticatorData', 8192),
            signature: bytes(reply.metadata, 'signature', 72),
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
