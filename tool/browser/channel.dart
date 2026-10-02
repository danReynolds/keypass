import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

// EXPERIMENT ONLY. See doc/browser-probe.md. Not a qualified Keypass backend.
const protocol = 'keypass-browser-probe-v1';

Uint8List randomBytes(int count) {
  final random = Random.secure();
  return Uint8List.fromList(List.generate(count, (_) => random.nextInt(256)));
}

String encodeBytes(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');
Uint8List decodeBytes(String value, {required int length}) {
  if (!RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(value) ||
      value.length != (length * 8 + 5) ~/ 6) {
    throw const FormatException('Invalid encoding');
  }
  final bytes = base64Url.decode(base64Url.normalize(value));
  if (bytes.length != length || encodeBytes(bytes) != value) {
    throw const FormatException('Invalid encoding');
  }
  return bytes;
}

String transcript({
  required String origin,
  required String domain,
  required String session,
  required List<int> serverPublicKey,
  required List<int> browserPublicKey,
}) => jsonEncode([
  protocol,
  origin,
  domain,
  session,
  encodeBytes(serverPublicKey),
  encodeBytes(browserPublicKey),
]);

final class ProbeChannel {
  ProbeChannel._(
    this._writeKey,
    this._readKey,
    this._salt,
    this._server,
    this.code,
  );
  final SecretKey _writeKey;
  final SecretKey _readKey;
  final List<int> _salt;
  final bool _server;
  final String code;
  final _cipher = AesGcm.with256bits();
  int _sent = 0;
  int _received = 0;
  bool _closed = false;
  bool _writing = false;
  bool _reading = false;

  static Future<ProbeChannel> derive({
    required SimpleKeyPair keyPair,
    required List<int> remotePublicKey,
    required String transcript,
    required bool server,
  }) async {
    if (remotePublicKey.length != 32) {
      throw const FormatException('Invalid peer');
    }
    final shared = await X25519().sharedSecretKey(
      keyPair: keyPair,
      remotePublicKey: SimplePublicKey(
        remotePublicKey,
        type: KeyPairType.x25519,
      ),
    );
    SecretKey? writeKey;
    SecretKey? readKey;
    SecretKey? confirmation;
    try {
      final exported = await shared.extractBytes();
      if (exported.every((b) => b == 0)) {
        throw const FormatException('Invalid peer');
      }
      final salt = (await Sha256().hash(utf8.encode(transcript))).bytes;
      Future<SecretKey> key(String label, int length) =>
          Hkdf(hmac: Hmac.sha256(), outputLength: length).deriveKey(
            secretKey: shared,
            nonce: salt,
            info: utf8.encode('$protocol/$label'),
          );
      writeKey = await key(server ? 's2b' : 'b2s', 32);
      readKey = await key(server ? 'b2s' : 's2b', 32);
      confirmation = await key('confirmation', 16);
      final bytes = await confirmation.extractBytes();
      final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      final code = [
        for (var i = 0; i < hex.length; i += 4) hex.substring(i, i + 4),
      ].join(' ');
      return ProbeChannel._(writeKey, readKey, salt, server, code);
    } catch (_) {
      writeKey?.destroy();
      readKey?.destroy();
      rethrow;
    } finally {
      confirmation?.destroy();
      shared.destroy();
    }
  }

  List<int> _aad(bool writing, int sequence) => [
    ..._salt,
    ...utf8.encode('/${writing == _server ? 's2b' : 'b2s'}/$sequence'),
  ];
  Uint8List _nonce(int sequence) =>
      Uint8List(12)..buffer.asByteData().setUint32(8, sequence);

  Future<Uint8List> seal(List<int> plaintext) async {
    if (_closed ||
        _writing ||
        _sent >= 0xffffffff ||
        plaintext.length > 16384) {
      throw StateError('Channel unavailable');
    }
    _writing = true;
    final sequence = _sent++;
    try {
      final box = await _cipher.encrypt(
        plaintext,
        secretKey: _writeKey,
        nonce: _nonce(sequence),
        aad: _aad(true, sequence),
      );
      if (_closed) throw StateError('Channel closed');
      final header = Uint8List(4)..buffer.asByteData().setUint32(0, sequence);
      return Uint8List.fromList([
        ...header,
        ...box.cipherText,
        ...box.mac.bytes,
      ]);
    } finally {
      _writing = false;
    }
  }

  Future<Uint8List> open(Uint8List frame) async {
    if (_closed || _reading || frame.length < 20 || frame.length > 16404) {
      throw StateError('Invalid frame');
    }
    final sequence = ByteData.sublistView(frame, 0, 4).getUint32(0);
    if (sequence != _received) throw StateError('Unexpected sequence');
    _reading = true;
    try {
      final clear = await _cipher.decrypt(
        SecretBox(
          frame.sublist(4, frame.length - 16),
          nonce: _nonce(sequence),
          mac: Mac(frame.sublist(frame.length - 16)),
        ),
        secretKey: _readKey,
        aad: _aad(false, sequence),
      );
      if (_closed) {
        clear.fillRange(0, clear.length, 0);
        throw StateError('Channel closed');
      }
      _received++;
      final result = Uint8List.fromList(clear);
      clear.fillRange(0, clear.length, 0);
      return result;
    } finally {
      _reading = false;
    }
  }

  void close() {
    _closed = true;
    _writeKey.destroy();
    _readKey.destroy();
  }
}
