import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'channel.dart';

/// Bounded, one-peer, one-result prototype. Not registered in the public SDK.
final class ProbeBridge {
  ProbeBridge._(
    this._server,
    this._keyPair,
    this.publicKey,
    this.helper,
    this.domain,
    this.request,
    this.confirmPairing,
  ) : session = encodeBytes(randomBytes(24));
  final HttpServer _server;
  final SimpleKeyPair _keyPair;
  final List<int> publicKey;
  final Uri helper;
  final String domain;
  final Map<String, Object?> request;
  final Future<bool> Function(String code) confirmPairing;
  final String session;
  final _result = Completer<Uint8List>();
  ProbeChannel? _channel;
  Future<bool>? _approval;
  Timer? _timer;
  bool _claimed = false;
  bool _confirming = false;
  bool _paired = false;
  bool _returning = false;
  bool _closed = false;

  Future<Uint8List> get result => _result.future;
  Uri get endpoint => Uri.parse('http://127.0.0.1:${_server.port}/$session');
  Uri get launchUrl => helper.replace(
    fragment: Uri(
      queryParameters: {
        'endpoint': '$endpoint',
        'key': encodeBytes(publicKey),
        'session': session,
        'rp': domain,
      },
    ).query,
  );

  static Future<ProbeBridge> start({
    required Uri helper,
    required String domain,
    required Map<String, Object?> request,
    required Future<bool> Function(String code) confirmPairing,
    bool allowLoopback = false,
    Duration deadline = const Duration(minutes: 8),
  }) async {
    final local =
        helper.scheme == 'http' &&
        helper.host == 'localhost' &&
        domain == 'localhost' &&
        allowLoopback;
    if ((!local && helper.scheme != 'https') ||
        helper.userInfo.isNotEmpty ||
        helper.hasFragment ||
        helper.hasQuery ||
        domain.isEmpty ||
        domain != domain.toLowerCase() ||
        !(helper.host == domain || helper.host.endsWith('.$domain')) ||
        deadline <= Duration.zero ||
        deadline > const Duration(minutes: 10)) {
      throw ArgumentError(
        'Use an RP-compatible HTTPS helper without query/fragment',
      );
    }
    final pair = await X25519().newKeyPair();
    HttpServer server;
    try {
      server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    } catch (_) {
      pair.destroy();
      rethrow;
    }
    final public = await pair.extractPublicKey();
    final bridge = ProbeBridge._(
      server,
      pair,
      public.bytes,
      helper,
      domain,
      Map.unmodifiable({
        ...request,
        'expiresAt': DateTime.now().add(deadline).millisecondsSinceEpoch,
      }),
      confirmPairing,
    );
    bridge._timer = Timer(deadline, () => bridge._fail('Probe timed out'));
    server.listen(
      bridge._handle,
      onError: (_) => bridge._fail('Bridge failed'),
    );
    return bridge;
  }

  Future<void> _handle(HttpRequest http) async {
    try {
      http.response.headers
        ..set('Cache-Control', 'no-store')
        ..set('X-Content-Type-Options', 'nosniff');
      if (_closed ||
          http.headers.value('host') != '127.0.0.1:${_server.port}' ||
          http.headers.value('origin') != helper.origin ||
          http.uri.hasQuery ||
          ![
            '/$session/hello',
            '/$session/confirm',
            '/$session/result',
            '/$session/abort',
          ].contains(http.uri.path)) {
        http.response.statusCode = HttpStatus.forbidden;
        return;
      }
      http.response.headers
        ..set('Access-Control-Allow-Origin', helper.origin)
        ..set('Vary', 'Origin');
      if (http.method == 'OPTIONS') {
        if (http.headers.value('access-control-request-method') != 'POST') {
          http.response.statusCode = HttpStatus.forbidden;
          return;
        }
        http.response.headers
          ..set('Access-Control-Allow-Methods', 'POST')
          ..set('Access-Control-Allow-Headers', 'content-type')
          ..set('Access-Control-Allow-Private-Network', 'true');
        http.response.statusCode = HttpStatus.noContent;
        return;
      }
      if (http.method != 'POST' ||
          http.headers.contentType?.mimeType != 'application/octet-stream') {
        http.response.statusCode = HttpStatus.methodNotAllowed;
        return;
      }
      final body = await _readBounded(http).timeout(const Duration(seconds: 5));
      if (_closed) return;
      if (http.uri.path.endsWith('/hello')) {
        if (_claimed || body.length != 32) {
          http.response.statusCode = HttpStatus.conflict;
          return;
        }
        _claimed = true;
        final channel = await ProbeChannel.derive(
          keyPair: _keyPair,
          remotePublicKey: body,
          transcript: transcript(
            origin: helper.origin,
            domain: domain,
            session: session,
            serverPublicKey: publicKey,
            browserPublicKey: body,
          ),
          server: true,
        );
        _keyPair.destroy();
        if (_closed) {
          channel.close();
          return;
        }
        _channel = channel;
        _approval = Future.sync(
          () => confirmPairing(channel.code),
        ).then((approved) => !_closed && approved, onError: (_) => false);
        http.response.statusCode = HttpStatus.noContent;
      } else if (http.uri.path.endsWith('/abort')) {
        if (_channel == null) {
          http.response.statusCode = HttpStatus.conflict;
          return;
        }
        final message = await _channel!.open(body);
        final valid = message.length == 1 && message[0] == 0;
        message.fillRange(0, message.length, 0);
        if (!valid) throw StateError('Invalid cancellation');
        http.response.statusCode = HttpStatus.noContent;
        await http.response.close();
        _fail('Probe cancelled');
      } else if (http.uri.path.endsWith('/confirm')) {
        if (_channel == null || _confirming) {
          http.response.statusCode = HttpStatus.conflict;
          return;
        }
        _confirming = true;
        final confirmation = await _channel!.open(body);
        final valid = confirmation.length == 1 && confirmation[0] == 1;
        confirmation.fillRange(0, confirmation.length, 0);
        if (!valid || !await _approval!) throw StateError('Pairing rejected');
        if (_closed) return;
        final clear = Uint8List.fromList(utf8.encode(jsonEncode(request)));
        try {
          final encrypted = await _channel!.seal(clear);
          if (_closed) return;
          _paired = true;
          http.response.headers.contentType = ContentType.binary;
          http.response.add(encrypted);
        } finally {
          clear.fillRange(0, clear.length, 0);
        }
      } else {
        if (!_paired || _returning || _channel == null) {
          http.response.statusCode = HttpStatus.conflict;
          return;
        }
        _returning = true;
        final clear = await _channel!.open(body);
        if (_closed || _result.isCompleted) {
          clear.fillRange(0, clear.length, 0);
          return;
        }
        if (clear.isEmpty || clear[0] != 1 || clear.length < 34) {
          clear.fillRange(0, clear.length, 0);
          throw StateError('Probe failed');
        }
        http.response.statusCode = HttpStatus.noContent;
        try {
          await http.response.close();
          if (_closed || _result.isCompleted) {
            clear.fillRange(0, clear.length, 0);
            return;
          }
          _result.complete(clear);
        } catch (_) {
          clear.fillRange(0, clear.length, 0);
          rethrow;
        }
        await close();
      }
    } catch (_) {
      try {
        http.response.statusCode = HttpStatus.badRequest;
        await http.response.close();
      } catch (_) {}
      _fail('Probe failed');
    } finally {
      try {
        await http.response.close();
      } catch (_) {}
    }
  }

  Future<Uint8List> _readBounded(HttpRequest request) async {
    if (request.contentLength > 16404) throw StateError('Oversized frame');
    final builder = BytesBuilder(copy: false);
    await for (final chunk in request) {
      if (builder.length + chunk.length > 16404) {
        throw StateError('Oversized frame');
      }
      builder.add(chunk);
    }
    return builder.takeBytes();
  }

  void _fail(String reason) {
    if (!_result.isCompleted) _result.completeError(StateError(reason));
    unawaited(close());
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _timer?.cancel();
    _keyPair.destroy();
    _channel?.close();
    if (!_result.isCompleted) {
      _result.completeError(StateError('Probe cancelled'));
    }
    await _server.close(force: true);
  }
}
