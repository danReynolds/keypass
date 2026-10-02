import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'channel.dart';

// A probe-only encrypted marker proves that a later process got the same PRF.
// It is not a vault envelope or the proposed public binding format.
final _marker = utf8.encode('keypass browser probe restart check v1');
Future<SecretKey> _key(Uint8List prf) async {
  if (prf.length != 32) throw const FormatException('Invalid PRF');
  final material = SecretKeyData(Uint8List.fromList(prf));
  try {
    return await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: material,
      info: utf8.encode('keypass-browser-probe-v1/restart-check'),
    );
  } finally {
    material.destroy();
  }
}

Future<Map<String, Object>> createRestartCheck(
  Uint8List prf,
  Map<String, Object?> binding,
) async {
  final key = await _key(prf);
  try {
    final box = await AesGcm.with256bits().encrypt(
      _marker,
      secretKey: key,
      nonce: randomBytes(12),
      aad: utf8.encode(jsonEncode(binding)),
    );
    return {
      'nonce': encodeBytes(box.nonce),
      'ciphertext': encodeBytes(box.cipherText),
      'tag': encodeBytes(box.mac.bytes),
    };
  } finally {
    key.destroy();
  }
}

Future<void> verifyRestartCheck(
  Uint8List prf,
  Map<String, Object?> binding,
  Map<String, Object?> saved,
) async {
  final key = await _key(prf);
  List<int>? clear;
  try {
    clear = await AesGcm.with256bits().decrypt(
      SecretBox(
        decodeBytes(saved['ciphertext'] as String, length: _marker.length),
        nonce: decodeBytes(saved['nonce'] as String, length: 12),
        mac: Mac(decodeBytes(saved['tag'] as String, length: 16)),
      ),
      secretKey: key,
      aad: utf8.encode(jsonEncode(binding)),
    );
    if (utf8.decode(clear) != utf8.decode(_marker)) {
      throw const FormatException('Wrong restart marker');
    }
  } finally {
    clear?.fillRange(0, clear.length, 0);
    key.destroy();
  }
}
