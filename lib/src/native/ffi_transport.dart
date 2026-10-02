import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../cancellation.dart';
import '../models.dart';
import 'backend.dart';

/// Versioned, polling C ABI: no Dart callback may outlive an isolate. Native UI
/// runs on the OS main thread; this isolate never blocks it waiting for a user.
final class FfiNativeTransport implements NativeTransport {
  FfiNativeTransport({DynamicLibrary? library}) : _library = library;
  DynamicLibrary? _library;
  bool _disposed = false;

  DynamicLibrary get _lib {
    if (_library case final library?) return library;
    try {
      final process = DynamicLibrary.process();
      if (process.providesSymbol('keypass_abi_version')) {
        return _library = process;
      }
      if (Platform.isAndroid) {
        return _library = DynamicLibrary.open('libkeypass.so');
      }
      final executable = File(Platform.resolvedExecutable).parent;
      if (Platform.isMacOS) {
        return _library = DynamicLibrary.open(
          '${executable.path}/../Frameworks/libkeypass.dylib',
        );
      }
      if (Platform.isWindows) {
        return _library = DynamicLibrary.open('${executable.path}/keypass.dll');
      }
    } catch (_) {
      /* Missing host integration is a typed, prompt-free result. */
    }
    throw const PasskeyException(PasskeyErrorCode.backendUnavailable);
  }

  @override
  Future<NativeReply> exchange(
    Map<String, Object?> request,
    PasskeyCancellation cancellation,
  ) async {
    if (_disposed) throw const PasskeyException(PasskeyErrorCode.disposed);
    if (cancellation.isCancelled) {
      throw const PasskeyException(PasskeyErrorCode.cancelled);
    }
    final lib = _lib;
    final version = lib.lookupFunction<Uint32 Function(), int Function()>(
      'keypass_abi_version',
    );
    if (version() != 1) {
      throw const PasskeyException(PasskeyErrorCode.backendUnavailable);
    }
    final start = lib
        .lookupFunction<
          Uint64 Function(Pointer<Uint8>, Uint32),
          int Function(Pointer<Uint8>, int)
        >('keypass_start');
    final poll = lib
        .lookupFunction<
          Pointer<Uint8> Function(Uint64, Pointer<Uint32>),
          Pointer<Uint8> Function(int, Pointer<Uint32>)
        >('keypass_poll');
    final cancel = lib
        .lookupFunction<Void Function(Uint64), void Function(int)>(
          'keypass_cancel',
        );
    final release = lib
        .lookupFunction<
          Void Function(Pointer<Uint8>, Uint32),
          void Function(Pointer<Uint8>, int)
        >('keypass_free');
    final encoded = utf8.encode(jsonEncode(request));
    if (encoded.length > 262144) {
      throw const PasskeyException(PasskeyErrorCode.invalidRequest);
    }
    final input = calloc<Uint8>(encoded.length);
    final size = calloc<Uint32>();
    int id;
    try {
      input.asTypedList(encoded.length).setAll(0, encoded);
      id = start(input, encoded.length);
    } finally {
      calloc.free(input);
    }
    if (id == 0) {
      calloc.free(size);
      throw const PasskeyException(PasskeyErrorCode.busy);
    }
    final timer = Stopwatch()..start();
    PasskeyErrorCode? cancelled;
    try {
      while (true) {
        if (cancelled == null &&
            (cancellation.isCancelled || timer.elapsed.inSeconds >= 125)) {
          cancelled = cancellation.isCancelled
              ? PasskeyErrorCode.cancelled
              : PasskeyErrorCode.timeout;
          cancel(id);
        }
        final pointer = poll(id, size);
        if (pointer != nullptr) {
          try {
            final length = size.value;
            if (length < 12 || length > 65580) {
              throw const PasskeyException(PasskeyErrorCode.backendFailure);
            }
            if (cancelled != null) throw PasskeyException(cancelled);
            final buffer = pointer.asTypedList(length);
            final header = ByteData.sublistView(buffer, 0, 12);
            final status = header.getUint32(0, Endian.little);
            final metadataLength = header.getUint32(4, Endian.little);
            final secretLength = header.getUint32(8, Endian.little);
            if (metadataLength > 65536 ||
                ![0, 32].contains(secretLength) ||
                length != 12 + metadataLength + secretLength) {
              throw const PasskeyException(PasskeyErrorCode.backendFailure);
            }
            final metadata = jsonDecode(
              utf8.decode(
                Uint8List.sublistView(buffer, 12, 12 + metadataLength),
              ),
            );
            if (metadata is! Map<String, dynamic>) {
              throw const PasskeyException(PasskeyErrorCode.backendFailure);
            }
            if (status != 0) {
              final codes = PasskeyErrorCode.values.where(
                (c) => c.name == metadata['error'],
              );
              throw PasskeyException(
                codes.length == 1
                    ? codes.single
                    : PasskeyErrorCode.backendFailure,
              );
            }
            return NativeReply(
              metadata,
              Uint8List.fromList(
                Uint8List.sublistView(buffer, 12 + metadataLength),
              ),
            );
          } finally {
            release(pointer, size.value);
          }
        }
        // Every native cancel completes a response immediately, even if the OS
        // later delivers a callback. A broken ABI cannot hold disposal forever.
        if (timer.elapsed.inSeconds >= 130) {
          throw const PasskeyException(PasskeyErrorCode.backendFailure);
        }
        await Future<void>.delayed(const Duration(milliseconds: 20));
      }
    } finally {
      calloc.free(size);
    }
  }

  @override
  Future<void> dispose() async {
    _disposed = true;
  }
}
