import 'dart:convert';
import 'dart:typed_data';

/// The access route is part of the integrity-protected credential binding.
enum PasskeyRoute { system, hardware }

enum PasskeyErrorCode {
  configurationMissing,
  backendUnavailable,
  hostUnavailable,
  domainAssociationRejected,
  credentialUnavailable,
  prfUnavailable,
  selectionUnsupported,
  deviceUnavailable,
  deviceSelectionRequired,
  verificationUnavailable,
  pinRequired,
  pinInvalid,
  pinBlocked,
  pinTemporarilyBlocked,
  pinChangeRequired,
  credentialStorageFull,
  cancelled,
  timeout,
  busy,
  disposed,
  invalidRequest,
  invalidBinding,
  verificationFailed,
  inconsistentSecret,
  backendFailure,
}

/// Stable, redacted error. Raw provider diagnostics are deliberately excluded.
final class PasskeyException implements Exception {
  const PasskeyException(this.code);
  final PasskeyErrorCode code;

  @override
  String toString() => 'PasskeyException(${code.name})';
}

/// Readiness to *attempt* a ceremony, never proof of a provider's PRF support.
final class PasskeyAvailability {
  const PasskeyAvailability.ready({this.supportsMultipleBindings = false})
    : reason = null;

  // Keep the argument non-nullable even though the field also models readiness.
  const PasskeyAvailability.unavailable(PasskeyErrorCode reason)
    // ignore: prefer_initializing_formals
    : reason = reason,
      supportsMultipleBindings = false;

  final PasskeyErrorCode? reason;
  final bool supportsMultipleBindings;
  bool get canAttempt => reason == null;
}

/// Persisted WebAuthn backup flags and signature-counter verification state.
final class AuthenticatorState {
  AuthenticatorState({
    required this.backupEligible,
    required this.backupState,
    required this.signCount,
  }) {
    if (signCount < 0 ||
        signCount > 0xffffffff ||
        (backupState && !backupEligible)) {
      throw const PasskeyException(PasskeyErrorCode.invalidBinding);
    }
  }
  final bool backupEligible;
  final bool backupState;
  final int signCount;
}

/// Immutable, nonsecret credential metadata. Integrity-protect it with the data
/// it unlocks; deserialization is structural validation, not authentication.
///
/// This experimental encoding is not yet a stable storage format.
final class PasskeyBinding {
  PasskeyBinding({
    required String domain,
    required Uint8List credentialId,
    required Uint8List userId,
    required Uint8List publicKeyCose,
    required Uint8List input,
    required this.authenticatorState,
    this.route = PasskeyRoute.system,
    List<String> transports = const [],
  }) : transports = _transports(transports, route),
       domain = validateDomain(domain, PasskeyErrorCode.invalidBinding),
       credentialId = _bytes(credentialId, 1, 1024),
       userId = _bytes(userId, 1, 64),
       publicKeyCose = _bytes(publicKeyCose, 1, 4096),
       input = _bytes(input, 1, 1024) {
    if (route == PasskeyRoute.hardware && authenticatorState.backupEligible) {
      throw const PasskeyException(PasskeyErrorCode.invalidBinding);
    }
  }

  final PasskeyRoute route;

  /// Hints only; a transport change must not change credential identity.
  final List<String> transports;
  final AuthenticatorState authenticatorState;
  final String domain;
  final Uint8List credentialId;
  final Uint8List userId;

  /// Encoded COSE_Key. The adapter must validate its algorithm and parameters.
  final Uint8List publicKeyCose;

  /// Original WebAuthn PRF input, not a pre-hashed CTAP hmac-secret salt.
  final Uint8List input;

  Map<String, Object> toJson() => {
    'version': route == PasskeyRoute.system ? 2 : 3,
    if (route == PasskeyRoute.hardware) ...{
      'route': 'hardware',
      'verification': 'required',
      'transports': transports,
    },
    'prf': 'webauthn-prf-v1',
    'domain': domain,
    'credentialId': _encode(credentialId),
    'userId': _encode(userId),
    'publicKeyCose': _encode(publicKeyCose),
    'input': _encode(input),
    'backupEligible': authenticatorState.backupEligible,
    'backupState': authenticatorState.backupState,
    'signCount': authenticatorState.signCount,
  };

  factory PasskeyBinding.fromJson(Map<String, Object?> json) {
    final keys = {
      'version',
      if (json['version'] == 3) ...['route', 'verification', 'transports'],
      'prf',
      'domain',
      'credentialId',
      'userId',
      'publicKeyCose',
      'input',
      'backupEligible',
      'backupState',
      'signCount',
    };
    if (json.length != keys.length ||
        !keys.every(json.containsKey) ||
        json['version'] is! int ||
        ![2, 3].contains(json['version']) ||
        (json['version'] == 3 &&
            (json['route'] != 'hardware' ||
                json['verification'] != 'required' ||
                json['transports'] is! List ||
                (json['transports'] as List).any((v) => v is! String))) ||
        json['backupEligible'] is! bool ||
        json['backupState'] is! bool ||
        json['signCount'] is! int ||
        json['prf'] != 'webauthn-prf-v1' ||
        json['domain'] is! String) {
      throw const PasskeyException(PasskeyErrorCode.invalidBinding);
    }
    return PasskeyBinding(
      route: json['version'] == 3 ? PasskeyRoute.hardware : PasskeyRoute.system,
      transports: json['version'] == 3
          ? (json['transports'] as List).cast<String>()
          : const [],
      domain: json['domain']! as String,
      credentialId: _decode(json['credentialId'], 1024),
      userId: _decode(json['userId'], 64),
      publicKeyCose: _decode(json['publicKeyCose'], 4096),
      input: _decode(json['input'], 1024),
      authenticatorState: AuthenticatorState(
        backupEligible: json['backupEligible']! as bool,
        backupState: json['backupState']! as bool,
        signCount: json['signCount']! as int,
      ),
    );
  }

  PasskeyBinding withState(AuthenticatorState state) => PasskeyBinding(
    route: route,
    transports: transports,
    domain: domain,
    credentialId: credentialId,
    userId: userId,
    publicKeyCose: publicKeyCose,
    input: input,
    authenticatorState: state,
  );

  @override
  String toString() => route == PasskeyRoute.system
      ? 'PasskeyBinding(version: 2)'
      : 'PasskeyBinding(version: 3)';
}

String validateDomain(String value, PasskeyErrorCode code) {
  // A conservative ASCII DNS name contract. IDNs must use their A-label form.
  // Native association/origin validation still belongs to the platform adapter.
  final domain = value.toLowerCase();
  final labels = domain.split('.');
  final label = RegExp(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$');
  if (domain.length > 253 ||
      labels.length < 2 ||
      !labels.every(label.hasMatch) ||
      RegExp(r'^[0-9.]+$').hasMatch(domain)) {
    throw PasskeyException(code);
  }
  return domain;
}

Uint8List _bytes(Uint8List source, int min, int max) {
  if (source.length < min || source.length > max) {
    throw const PasskeyException(PasskeyErrorCode.invalidBinding);
  }
  return Uint8List.fromList(source).asUnmodifiableView();
}

String _encode(Uint8List bytes) => base64Url.encode(bytes).replaceAll('=', '');

Uint8List _decode(Object? value, int max) {
  if (value is! String ||
      value.isEmpty ||
      value.length > ((max + 2) ~/ 3) * 4 ||
      !RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(value)) {
    throw const PasskeyException(PasskeyErrorCode.invalidBinding);
  }
  try {
    final bytes = base64Url.decode(base64Url.normalize(value));
    if (bytes.length > max || _encode(bytes) != value) {
      throw const PasskeyException(PasskeyErrorCode.invalidBinding);
    }
    return bytes;
  } on FormatException {
    throw const PasskeyException(PasskeyErrorCode.invalidBinding);
  }
}

List<String> _transports(List<String> values, PasskeyRoute route) {
  if (values.length > 2 ||
      values.toSet().length != values.length ||
      values.any((v) => !const ['usb', 'nfc'].contains(v)) ||
      (route == PasskeyRoute.system && values.isNotEmpty)) {
    throw const PasskeyException(PasskeyErrorCode.invalidBinding);
  }
  return List.unmodifiable(values);
}
