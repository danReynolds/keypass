import 'dart:convert';
import 'dart:typed_data';

import 'package:keypass/src/models.dart';
import 'package:keypass/src/webauthn/verifier.dart';
import 'channel.dart';

/// The SDK verifier is the single authority for ceremony evidence. The browser
/// transports raw evidence; no secret may be used before this returns.
PasskeyBinding verifyProbeEvidence({
  required Map<String, Object?> request,
  required String origin,
  required Map<String, Object?> metadata,
  bool allowLocalhost = false,
}) {
  _fields(metadata, {'version', 'registration', 'assertions'});
  if (metadata['version'] != 2 || request['version'] != 2) _bad();
  final domain = request['domain'] as String;
  final verifier = WebAuthnVerifier(
    domain: domain,
    origin: origin,
    allowLocalhost: allowLocalhost,
  );
  final saved = request['binding'];
  late PasskeyBinding binding;
  if (saved == null) {
    final registration = _map(metadata['registration']);
    _fields(registration, {
      'credentialId',
      'clientDataJSON',
      'attestationObject',
      'prfEnabled',
    });
    final verified = verifier.registration(
      challenge: _bytes(request['registrationChallenge'], 32),
      credentialId: _bytes(registration['credentialId'], 1024),
      clientDataJSON: _bytes(registration['clientDataJSON'], 4096),
      attestationObject: _bytes(registration['attestationObject'], 16384),
      prfEnabled: registration['prfEnabled'] == true,
    );
    binding = PasskeyBinding(
      domain: domain,
      credentialId: verified.credentialId,
      userId: _bytes(request['userId'], 64),
      publicKeyCose: verified.publicKeyCose,
      input: _bytes(request['input'], 1024),
      authenticatorState: verified.state,
    );
  } else {
    if (metadata['registration'] != null) _bad();
    binding = PasskeyBinding.fromJson(_map(saved));
    if (binding.route != PasskeyRoute.system ||
        binding.domain != domain ||
        encodeBytes(binding.input) != request['input'] ||
        encodeBytes(binding.userId) != request['userId']) {
      _bad();
    }
  }
  final assertions = metadata['assertions'];
  final challenges = request['challenges'];
  if (assertions is! List ||
      assertions.length != 2 ||
      challenges is! List ||
      challenges.length != 2 ||
      challenges[0] == challenges[1]) {
    _bad();
  }
  for (var i = 0; i < 2; i++) {
    final assertion = _map(assertions[i]);
    _fields(assertion, {
      'credentialId',
      'clientDataJSON',
      'authenticatorData',
      'signature',
      'userHandle',
    });
    binding = binding.withState(
      verifier.assertion(
        challenge: _bytes(challenges[i], 32),
        credentialId: _bytes(assertion['credentialId'], 1024),
        expectedCredentialId: binding.credentialId,
        expectedUserId: binding.userId,
        userHandle: assertion['userHandle'] == null
            ? null
            : _bytes(assertion['userHandle'], 64),
        publicKeyCose: binding.publicKeyCose,
        clientDataJSON: _bytes(assertion['clientDataJSON'], 4096),
        authenticatorData: _bytes(assertion['authenticatorData'], 8192),
        signature: _bytes(assertion['signature'], 72),
        previousState: binding.authenticatorState,
      ),
    );
  }
  return binding;
}

Map<String, Object?> _map(Object? value) {
  if (value is! Map<String, Object?>) _bad();
  return value;
}

void _fields(Map<String, Object?> map, Set<String> keys) {
  if (map.length != keys.length || !keys.every(map.containsKey)) _bad();
}

Uint8List _bytes(Object? value, int max) {
  if (value is! String || value.isEmpty || value.length > (max * 8 + 5) ~/ 6) {
    _bad();
  }
  if (!RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(value)) _bad();
  final bytes = base64Url.decode(base64Url.normalize(value));
  if (bytes.length > max || encodeBytes(bytes) != value) _bad();
  return bytes;
}

Never _bad() => throw const FormatException('Invalid probe evidence');
