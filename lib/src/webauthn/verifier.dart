import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;
import 'package:pointycastle/signers/ecdsa_signer.dart';

import '../models.dart';
import 'bounded_cbor.dart';
import 'client_data.dart';

export '../models.dart' show AuthenticatorState;

/// Internal verifier profile: top-level WebAuthn, ES256/P-256, UV required,
/// attestation "none". No AppID, related origins, cross-origin frames, or trust
/// assertion about hardware provenance. PRF bytes remain trusted client output;
/// a WebAuthn signature does not independently authenticate those bytes.
final class WebAuthnVerifier {
  WebAuthnVerifier({
    required this.domain,
    required this.origin,
    bool allowLocalhost = false,
    bool androidAppOrigin = false,
  }) : _direct = false {
    if (androidAppOrigin) {
      validateDomain(domain, PasskeyErrorCode.invalidRequest);
      if (!RegExp(
        r'^android:apk-key-hash:[A-Za-z0-9_-]{43}$',
      ).hasMatch(origin)) {
        throw const PasskeyException(PasskeyErrorCode.invalidRequest);
      }
      final hash = origin.substring('android:apk-key-hash:'.length);
      if (_encode(base64Url.decode(base64Url.normalize(hash))) != hash) {
        throw const PasskeyException(PasskeyErrorCode.invalidRequest);
      }
      return;
    }
    final uri = Uri.tryParse(origin);
    final local =
        allowLocalhost &&
        domain == 'localhost' &&
        uri?.host == 'localhost' &&
        uri?.scheme == 'http';
    if (!local) {
      validateDomain(domain, PasskeyErrorCode.invalidRequest);
    }
    if (domain != domain.toLowerCase() ||
        uri == null ||
        (!local && uri.scheme != 'https') ||
        uri.userInfo.isNotEmpty ||
        uri.path.isNotEmpty ||
        uri.hasQuery ||
        uri.hasFragment ||
        uri.origin != origin ||
        !(uri.host == domain || uri.host.endsWith('.$domain'))) {
      throw const PasskeyException(PasskeyErrorCode.invalidRequest);
    }
  }

  /// Direct CTAP profile: no invented browser origin or local app attestation.
  WebAuthnVerifier.hardware({required this.domain})
    : origin = '',
      _direct = true {
    validateDomain(domain, PasskeyErrorCode.invalidRequest);
  }

  final bool _direct;
  final String domain;
  final String origin;

  /// Native transport must first verify the CTAP attestation statement against
  /// this ceremony's client hash. Certificate-chain trust is not claimed.
  VerifiedRegistration hardwareRegistration({
    required Uint8List credentialId,
    required Uint8List authenticatorData,
  }) => _guard(() {
    if (!_direct) _bad();
    _length(credentialId, 1, 1024);
    final auth = _auth(authenticatorData, registration: true);
    if (!_equal(auth.credentialId!, credentialId) ||
        auth.state.backupEligible ||
        auth.extensions['hmac-secret'] != true ||
        auth.extensions['credProtect'] != 3) {
      _bad();
    }
    _key(auth.publicKeyCose!);
    return VerifiedRegistration(credentialId, auth.publicKeyCose!, auth.state);
  });

  AuthenticatorState hardwareAssertion({
    required Uint8List clientDataHash,
    required Uint8List credentialId,
    required PasskeyBinding binding,
    required Uint8List? userHandle,
    required Uint8List authenticatorData,
    required Uint8List signature,
  }) => _guard(() {
    if (!_direct ||
        binding.route != PasskeyRoute.hardware ||
        binding.domain != domain) {
      _bad();
    }
    _length(clientDataHash, 32, 32);
    final auth = _auth(authenticatorData, registration: false);
    final encrypted = auth.extensions['hmac-secret'];
    if (auth.state.backupEligible ||
        encrypted is! Uint8List ||
        ![32, 48].contains(encrypted.length)) {
      _bad();
    }
    return _assertionData(
      clientDataHash: clientDataHash,
      credentialId: credentialId,
      expectedCredentialId: binding.credentialId,
      expectedUserId: binding.userId,
      userHandle: userHandle,
      publicKeyCose: binding.publicKeyCose,
      authenticatorData: authenticatorData,
      signature: signature,
      previousState: binding.authenticatorState,
    );
  });

  VerifiedRegistration registration({
    required Uint8List challenge,
    required Uint8List credentialId,
    required Uint8List clientDataJSON,
    required Uint8List attestationObject,
    required bool prfEnabled,
  }) => _guard(() {
    _client(clientDataJSON, challenge, 'webauthn.create');
    _length(credentialId, 1, 1024);
    final attestation = BoundedCbor(attestationObject).readAll();
    if (attestation is! Map ||
        attestation.length != 3 ||
        attestation['fmt'] != 'none' ||
        attestation['attStmt'] is! Map ||
        (attestation['attStmt'] as Map).isNotEmpty ||
        attestation['authData'] is! Uint8List) {
      _bad();
    }
    final auth = _auth(
      attestation['authData'] as Uint8List,
      registration: true,
    );
    if (!_equal(auth.credentialId!, credentialId)) _bad();
    _key(auth.publicKeyCose!);
    if (!prfEnabled) {
      throw const PasskeyException(PasskeyErrorCode.prfUnavailable);
    }
    return VerifiedRegistration(credentialId, auth.publicKeyCose!, auth.state);
  });

  /// [previousState] must be the state saved with the enrolled credential.
  /// null is reserved for the legacy standalone probe, which did not store it.
  /// New adapters must retain BE and counter state and pass it on every call.
  AuthenticatorState assertion({
    required Uint8List challenge,
    required Uint8List credentialId,
    required Uint8List expectedCredentialId,
    required Uint8List expectedUserId,
    required Uint8List? userHandle,
    required Uint8List publicKeyCose,
    required Uint8List clientDataJSON,
    required Uint8List authenticatorData,
    required Uint8List signature,
    required AuthenticatorState? previousState,
  }) => _guard(() {
    _client(clientDataJSON, challenge, 'webauthn.get');
    return _assertionData(
      clientDataHash: _hash(clientDataJSON),
      credentialId: credentialId,
      expectedCredentialId: expectedCredentialId,
      expectedUserId: expectedUserId,
      userHandle: userHandle,
      publicKeyCose: publicKeyCose,
      authenticatorData: authenticatorData,
      signature: signature,
      previousState: previousState,
    );
  });

  AuthenticatorState _assertionData({
    required Uint8List clientDataHash,
    required Uint8List credentialId,
    required Uint8List expectedCredentialId,
    required Uint8List expectedUserId,
    required Uint8List? userHandle,
    required Uint8List publicKeyCose,
    required Uint8List authenticatorData,
    required Uint8List signature,
    required AuthenticatorState? previousState,
  }) {
    _length(credentialId, 1, 1024);
    _length(expectedCredentialId, 1, 1024);
    _length(expectedUserId, 1, 64);
    if (!_equal(credentialId, expectedCredentialId) ||
        (userHandle != null && !_equal(userHandle, expectedUserId))) {
      _bad();
    }
    final auth = _auth(authenticatorData, registration: false);
    if (previousState != null) {
      if (auth.state.backupEligible != previousState.backupEligible) _bad();
      // Explicit conservative counter policy. Both zero is valid for synced
      // passkeys. A nonzero counter must increase; never guess that a rollback
      // is safe. Applications must commit returned state with their metadata.
      if ((auth.state.signCount != 0 || previousState.signCount != 0) &&
          auth.state.signCount <= previousState.signCount) {
        _bad();
      }
    }
    final signer = ECDSASigner(SHA256Digest())
      ..init(false, PublicKeyParameter<ECPublicKey>(_key(publicKeyCose)));
    final signed = Uint8List.fromList([
      ...authenticatorData,
      ...clientDataHash,
    ]);
    if (!signer.verifySignature(signed, _signature(signature))) _bad();
    return auth.state;
  }

  void _client(Uint8List bytes, Uint8List challenge, String type) {
    if (_direct) _bad();
    _length(challenge, 32, 32);
    final client = parseClientData(bytes);
    if (client['type'] != type ||
        client['challenge'] != _encode(challenge) ||
        client['origin'] != origin ||
        (client.containsKey('crossOrigin') && client['crossOrigin'] != false) ||
        client.containsKey('topOrigin')) {
      _bad();
    }
  }

  _Auth _auth(Uint8List bytes, {required bool registration}) {
    _length(bytes, 37, 8192);
    if (!_equal(
      Uint8List.sublistView(bytes, 0, 32),
      _hash(utf8.encode(domain)),
    )) {
      _bad();
    }
    final flags = bytes[32];
    if ((flags & 5) != 5 ||
        (flags & 0x22) != 0 ||
        ((flags & 0x10) != 0 && (flags & 8) == 0) ||
        ((flags & 0x40) != 0) != registration) {
      _bad();
    }
    final state = AuthenticatorState(
      backupEligible: (flags & 8) != 0,
      backupState: (flags & 0x10) != 0,
      signCount: ByteData.sublistView(bytes, 33, 37).getUint32(0),
    );
    var offset = 37;
    Uint8List? id, cose;
    if (registration) {
      if (bytes.length < 55) _bad();
      final length = ByteData.sublistView(bytes, 53, 55).getUint16(0);
      if (length < 1 || length > 1024 || 55 + length >= bytes.length) _bad();
      id = Uint8List.sublistView(bytes, 55, 55 + length);
      offset = 55 + length;
      final reader = BoundedCbor(bytes, offset: offset);
      if (reader.read() is! Map) _bad();
      cose = Uint8List.sublistView(bytes, offset, reader.offset);
      offset = reader.offset;
    }
    Map<Object?, Object?> extensions = const {};
    if ((flags & 0x80) != 0) {
      final reader = BoundedCbor(bytes, offset: offset);
      final decoded = reader.read();
      if (decoded is! Map || decoded.keys.any((key) => key is! String)) {
        _bad();
      }
      extensions = decoded;
      offset = reader.offset;
    }
    if (offset != bytes.length) _bad();
    return _Auth(state, id, cose, extensions);
  }
}

final class VerifiedRegistration {
  VerifiedRegistration(Uint8List id, Uint8List cose, this.state)
    : credentialId = Uint8List.fromList(id).asUnmodifiableView(),
      publicKeyCose = Uint8List.fromList(cose).asUnmodifiableView();
  final Uint8List credentialId;
  final Uint8List publicKeyCose;
  final AuthenticatorState state;
}

final class _Auth {
  _Auth(this.state, this.credentialId, this.publicKeyCose, this.extensions);
  final Map<Object?, Object?> extensions;
  final AuthenticatorState state;
  final Uint8List? credentialId;
  final Uint8List? publicKeyCose;
}

final _curve = ECCurve_secp256r1();
ECPublicKey _key(Uint8List cose) {
  _length(cose, 1, 4096);
  final map = BoundedCbor(cose).readAll();
  if (map is! Map ||
      map.length != 5 ||
      map[1] != 2 ||
      map[3] != -7 ||
      map[-1] != 1 ||
      map[-2] is! Uint8List ||
      map[-3] is! Uint8List) {
    _bad();
  }
  final xBytes = map[-2] as Uint8List, yBytes = map[-3] as Uint8List;
  _length(xBytes, 32, 32);
  _length(yBytes, 32, 32);
  final x = _integer(xBytes), y = _integer(yBytes);
  final curve = _curve.curve as fp.ECCurve;
  final prime = curve.q!;
  if (x >= prime ||
      y >= prime ||
      (y * y -
                  (x * x * x +
                      curve.a!.toBigInteger()! * x +
                      curve.b!.toBigInteger()!)) %
              prime !=
          BigInt.zero) {
    _bad();
  }
  // P-256 has cofactor 1: every non-infinity point on the curve is in the group.
  return ECPublicKey(curve.createPoint(x, y), _curve);
}

/// Exact P-256 SPKI conversion for legacy probe metadata, not a general ASN.1
/// parser. The SDK binding itself uses COSE and never requires SPKI.
Uint8List coseFromP256Spki(Uint8List spki) => _guard(() {
  const header = [
    0x30,
    0x59,
    0x30,
    0x13,
    0x06,
    0x07,
    0x2a,
    0x86,
    0x48,
    0xce,
    0x3d,
    0x02,
    0x01,
    0x06,
    0x08,
    0x2a,
    0x86,
    0x48,
    0xce,
    0x3d,
    0x03,
    0x01,
    0x07,
    0x03,
    0x42,
    0x00,
    0x04,
  ];
  if (spki.length != 91 ||
      !_equal(Uint8List.sublistView(spki, 0, 27), header)) {
    _bad();
  }
  final cose = Uint8List.fromList([
    0xa5,
    1,
    2,
    3,
    0x26,
    0x20,
    1,
    0x21,
    0x58,
    32,
    ...spki.sublist(27, 59),
    0x22,
    0x58,
    32,
    ...spki.sublist(59),
  ]);
  _key(cose);
  return cose;
});

bool sameP256Key(Uint8List first, Uint8List second) => _guard(() {
  return _equal(
    _key(first).Q!.getEncoded(false),
    _key(second).Q!.getEncoded(false),
  );
});

ECSignature _signature(Uint8List bytes) {
  _length(bytes, 8, 72);
  if (bytes[0] != 0x30 || bytes[1] != bytes.length - 2) _bad();
  var offset = 2;
  BigInt component() {
    if (offset + 2 > bytes.length || bytes[offset++] != 2) _bad();
    final length = bytes[offset++];
    if (length < 1 ||
        length > 33 ||
        offset + length > bytes.length ||
        (bytes[offset] & 0x80) != 0 ||
        (length > 1 && bytes[offset] == 0 && (bytes[offset + 1] & 0x80) == 0)) {
      _bad();
    }
    final n = _integer(Uint8List.sublistView(bytes, offset, offset + length));
    offset += length;
    if (n <= BigInt.zero || n >= _curve.n) _bad();
    return n;
  }

  final signature = ECSignature(component(), component());
  if (offset != bytes.length) _bad();
  return signature;
}

BigInt _integer(List<int> bytes) =>
    bytes.fold(BigInt.zero, (n, byte) => (n << 8) | BigInt.from(byte));
Uint8List _hash(List<int> bytes) =>
    SHA256Digest().process(Uint8List.fromList(bytes));
String _encode(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var difference = 0;
  for (var i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  return difference == 0;
}

void _length(Uint8List bytes, int min, int max) {
  if (bytes.length < min || bytes.length > max) _bad();
}

T _guard<T>(T Function() body) {
  try {
    return body();
  } on PasskeyException {
    rethrow;
  } catch (_) {
    return _bad();
  }
}

Never _bad() =>
    throw const PasskeyException(PasskeyErrorCode.verificationFailed);
