import 'dart:convert';
import 'dart:typed_data';

import 'package:keypass/src/webauthn/verifier.dart';

/// Independent verifier for the probe's public ceremony evidence. The caller
/// retains ownership of the separate PRF buffer and clears it on every failure.
/// A legacy saved SPKI binding needs no replacement passkey: its first signed
/// assertion establishes this run's baseline, then the next must preserve BE
/// and satisfy counter policy. Persistent counter/BE storage is still SDK work.
Map<String, Object?> verifyProbeEvidence({
  required Map<String, Object?> request,
  required String origin,
  required Map<String, Object?> metadata,
  bool allowLocalhost = false,
}) {
  _fields(metadata, {'version', 'binding', 'registration', 'assertions'});
  if (metadata['version'] != 1 || request['evidenceVersion'] != 1) _bad();
  final binding = _map(metadata['binding']);
  _fields(binding, {
    'version',
    'domain',
    'credentialId',
    'userId',
    'input',
    'publicKeySpki',
  });
  if (binding['version'] != 1 ||
      binding['domain'] != request['domain'] ||
      binding['userId'] != request['userId'] ||
      binding['input'] != request['input']) {
    _bad();
  }
  final expected = request['binding'];
  if (expected != null) {
    final saved = _map(expected);
    if (saved.length != binding.length ||
        binding.entries.any((e) => saved[e.key] != e.value)) {
      _bad();
    }
  }
  final verifier = WebAuthnVerifier(
    domain: binding['domain'] as String,
    origin: origin,
    allowLocalhost: allowLocalhost,
  );
  final id = _bytes(binding['credentialId'], 1024);
  final user = _bytes(binding['userId'], 64);
  final cose = coseFromP256Spki(_bytes(binding['publicKeySpki'], 1024));
  AuthenticatorState? state;
  if (expected == null) {
    final registration = _map(metadata['registration']);
    _fields(registration, {
      'credentialId',
      'clientDataJSON',
      'attestationObject',
      'prfEnabled',
    });
    if (registration['credentialId'] != binding['credentialId'] ||
        registration['prfEnabled'] != true) {
      _bad();
    }
    final verified = verifier.registration(
      challenge: _bytes(request['registrationChallenge'], 32),
      credentialId: id,
      clientDataJSON: _bytes(registration['clientDataJSON'], 4096),
      attestationObject: _bytes(registration['attestationObject'], 16384),
      prfEnabled: true,
    );
    if (!sameP256Key(verified.publicKeyCose, cose)) _bad();
    state = verified.state;
  } else if (metadata['registration'] != null) {
    _bad();
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
    state = verifier.assertion(
      challenge: _bytes(challenges[i], 32),
      credentialId: _bytes(assertion['credentialId'], 1024),
      expectedCredentialId: id,
      expectedUserId: user,
      userHandle: assertion['userHandle'] == null
          ? null
          : _bytes(assertion['userHandle'], 64),
      publicKeyCose: cose,
      clientDataJSON: _bytes(assertion['clientDataJSON'], 4096),
      authenticatorData: _bytes(assertion['authenticatorData'], 8192),
      signature: _bytes(assertion['signature'], 72),
      previousState: state,
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
  if (value is! String ||
      value.isEmpty ||
      value.length > (max * 8 + 5) ~/ 6 ||
      !RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(value)) {
    _bad();
  }
  final result = base64Url.decode(base64Url.normalize(value));
  if (result.length > max ||
      base64Url.encode(result).replaceAll('=', '') != value) {
    _bad();
  }
  return result;
}

Never _bad() => throw const FormatException('Invalid probe evidence');
