import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:keypass/keypass.dart';

Uint8List randomBytes(int count) {
  final random = Random.secure();
  return Uint8List.fromList(List.generate(count, (_) => random.nextInt(256)));
}

final marker = utf8.encode('Keypass native demo encrypted restart marker v1');
Future<SecretKey> derive(Uint8List secret) async {
  final input = SecretKeyData(Uint8List.fromList(secret));
  try {
    return await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: input,
      info: utf8.encode('keypass-native-demo-v1/restart-marker'),
    );
  } finally {
    input.destroy();
  }
}

Future<Map<String, Object?>> encryptMarker(
  SecretKey key,
  PasskeyRecord record,
) async {
  final box = await AesGcm.with256bits().encrypt(
    marker,
    secretKey: key,
    nonce: randomBytes(12),
    aad: utf8.encode(jsonEncode(record.toJson())),
  );
  return {
    'nonce': encode(box.nonce),
    'ciphertext': encode(box.cipherText),
    'tag': encode(box.mac.bytes),
  };
}

Future<void> decryptMarker(
  SecretKey key,
  PasskeyRecord record,
  Map<String, Object?> saved,
) async {
  final clear = await AesGcm.with256bits().decrypt(
    SecretBox(
      bytes(saved, 'ciphertext', 1024),
      nonce: bytes(saved, 'nonce', 12),
      mac: Mac(bytes(saved, 'tag', 16)),
    ),
    secretKey: key,
    aad: utf8.encode(jsonEncode(record.toJson())),
  );
  try {
    if (utf8.decode(clear) != utf8.decode(marker)) {
      throw const PasskeyException(PasskeyErrorCode.verificationFailed);
    }
  } finally {
    clear.fillRange(0, clear.length, 0);
  }
}

// Demo-only format, compatible with the original macOS AOT worker's marker.
// The application authenticates public binding metadata together with the marker.
final class DemoStore {
  DemoStore(this.file);
  final File file;
  bool get exists => file.existsSync();

  /// Import disposable hardware test ciphertext; authenticates on first unlock.
  /// The source is never deleted and an existing destination is never replaced.
  Future<void> importHardware(File source, {required String namespace}) async {
    if (exists) throw const PasskeyException(PasskeyErrorCode.invalidRequest);
    final saved = await DemoStore(source)._read();
    if (saved.record.route != PasskeyRoute.hardware ||
        saved.record.rpId != namespace) {
      throw const PasskeyException(PasskeyErrorCode.invalidBinding);
    }
    await _save(saved.record, saved.encrypted);
  }

  Future<void> enroll(
    Keypass passkeys, {
    required PasskeyCancellation cancellation,
  }) async {
    if (exists) {
      throw const PasskeyException(PasskeyErrorCode.invalidRequest);
    }
    final result = await passkeys.create(
      label: 'Keypass native demo',
      cancellation: cancellation,
    );
    SecretKey? key;
    try {
      key = await derive(result.secret);
      await _save(result.record, await encryptMarker(key, result.record));
    } finally {
      key?.destroy();
      result.dispose();
    }
  }

  Future<void> unlock(
    Keypass passkeys, {
    required PasskeyCancellation cancellation,
  }) async {
    if (!exists) {
      throw const PasskeyException(PasskeyErrorCode.credentialUnavailable);
    }
    // Structural corruption must be reported before requesting a provider.
    final saved = await _read();
    final result = await passkeys.unlock(
      saved.record,
      cancellation: cancellation,
    );
    SecretKey? key;
    try {
      key = await derive(result.secret);
      // The existing ciphertext authenticates the ORIGINAL saved record. Only
      // after decryption succeeds may we re-encrypt with advanced record state.
      await decryptMarker(key, saved.record, saved.encrypted);
      await _save(result.record, await encryptMarker(key, result.record));
    } finally {
      key?.destroy();
      result.dispose();
    }
  }

  Future<({PasskeyRecord record, Map<String, Object?> encrypted})>
  _read() async {
    try {
      if (await file.length() > 65536) {
        throw const FormatException('Invalid demo marker');
      }
      final value = jsonDecode(await file.readAsString());
      if (value is! Map<String, dynamic> ||
          value.length != 3 ||
          value['version'] is! int ||
          value['version'] != 1 ||
          value['binding'] is! Map<String, dynamic> ||
          value['encryptedMarker'] is! Map<String, dynamic>) {
        throw const FormatException('Invalid demo marker');
      }
      final encrypted = value['encryptedMarker'] as Map<String, dynamic>;
      if (encrypted.length != 3 ||
          bytes(encrypted, 'nonce', 12).length != 12 ||
          bytes(encrypted, 'tag', 16).length != 16 ||
          bytes(encrypted, 'ciphertext', 1024).length != marker.length) {
        throw const FormatException('Invalid demo marker');
      }
      return (
        record: PasskeyRecord.fromJson(
          value['binding'] as Map<String, dynamic>,
        ),
        encrypted: encrypted,
      );
    } on PasskeyException {
      rethrow;
    } catch (_) {
      throw const PasskeyException(PasskeyErrorCode.invalidBinding);
    }
  }

  Future<void> _save(
    PasskeyRecord record,
    Map<String, Object?> encrypted,
  ) async {
    await file.parent.create(recursive: true);
    final temporary = File('${file.path}.pending');
    await temporary.writeAsString(
      jsonEncode({
        'version': 1,
        'binding': record.toJson(),
        'encryptedMarker': encrypted,
      }),
      flush: true,
    );
    await temporary.rename(file.path);
  }
}

String encode(List<int> value) => base64Url.encode(value).replaceAll('=', '');
Uint8List bytes(Map<String, Object?> value, String field, int maximum) {
  final text = value[field];
  if (text is! String || text.length > ((maximum + 2) ~/ 3) * 4) {
    throw const FormatException('Invalid demo marker');
  }
  final decoded = base64Url.decode(base64Url.normalize(text));
  if (decoded.length > maximum || encode(decoded) != text) {
    throw const FormatException('Invalid demo marker');
  }
  return decoded;
}
