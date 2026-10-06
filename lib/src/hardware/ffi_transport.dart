import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../cancellation.dart';
import '../models.dart';
import '../native/backend.dart';
import 'interaction.dart';
import 'bindings.dart' as assets;

/// Dedicated hardware ABI: PINs and PRF output never enter JSON.
final class HardwareFfiTransport implements NativeTransport {
  HardwareFfiTransport(this.interaction, {DynamicLibrary? library})
    : _library = library;
  final HardwareInteraction interaction;
  DynamicLibrary? _library;
  bool _disposed = false;

  DynamicLibrary get _lib {
    if (_library case final library?) return library;
    try {
      final process = DynamicLibrary.process();
      if (process.providesSymbol('keypass_hardware_abi_version')) {
        return _library = process;
      }
      if (Platform.isAndroid) {
        return _library = DynamicLibrary.open('libkeypass_hardware.so');
      }
      if (!Platform.isMacOS && !Platform.isLinux) {
        throw const PasskeyException(PasskeyErrorCode.backendUnavailable);
      }
      const configured = String.fromEnvironment('KEYPASS_HARDWARE_LIBRARY');
      if (configured.isNotEmpty) {
        return _library = DynamicLibrary.open(configured);
      }
      final directory = File(Platform.resolvedExecutable).parent.path;
      final name = Platform.isMacOS
          ? 'libkeypass_hardware.dylib'
          : 'libkeypass_hardware.so';
      // Packaged beside a CLI executable; apps may link it into the process.
      return _library = DynamicLibrary.open('$directory/$name');
    } catch (_) {
      throw const PasskeyException(PasskeyErrorCode.backendUnavailable);
    }
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
    // Explicitly packaged AOT consumers retain their reviewed sibling-library
    // layout. Normal Dart/Flutter desktop execution uses the registered asset.
    const manualBundle = bool.fromEnvironment('keypass.hardware.manual_bundle');
    const configured = String.fromEnvironment('KEYPASS_HARDWARE_LIBRARY');
    final useAssets =
        _library == null &&
        (Platform.isMacOS || Platform.isLinux) &&
        !manualBundle &&
        configured.isEmpty;
    final lib = useAssets ? null : _lib;
    final version = useAssets
        ? assets.hardwareAbiVersion
        : lib!.lookupFunction<Uint32 Function(), int Function()>(
            'keypass_hardware_abi_version',
          );
    try {
      if (version() != 1) {
        throw const PasskeyException(PasskeyErrorCode.backendUnavailable);
      }
    } on ArgumentError {
      throw const PasskeyException(PasskeyErrorCode.backendUnavailable);
    }
    final start = useAssets
        ? assets.hardwareStart
        : lib!.lookupFunction<
            Uint64 Function(Pointer<Uint8>, Uint32),
            int Function(Pointer<Uint8>, int)
          >('keypass_hardware_start');
    final poll = useAssets
        ? assets.hardwarePoll
        : lib!.lookupFunction<
            Pointer<Uint8> Function(Uint64, Pointer<Uint32>),
            Pointer<Uint8> Function(int, Pointer<Uint32>)
          >('keypass_hardware_poll');
    final cancel = useAssets
        ? assets.hardwareCancel
        : lib!.lookupFunction<Void Function(Uint64), void Function(int)>(
            'keypass_hardware_cancel',
          );
    final submitPin = useAssets
        ? assets.hardwarePin
        : lib!.lookupFunction<
            Uint32 Function(Uint64, Pointer<Uint8>, Uint32),
            int Function(int, Pointer<Uint8>, int)
          >('keypass_hardware_pin');
    final release = useAssets
        ? assets.hardwareFree
        : lib!.lookupFunction<
            Void Function(Pointer<Uint8>, Uint32),
            void Function(Pointer<Uint8>, int)
          >('keypass_hardware_free');
    final encoded = utf8.encode(jsonEncode(request));
    if (encoded.isEmpty || encoded.length > 65536) {
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
    final promptSignal = PasskeyCancellation();
    final subscription = cancellation.onCancel.listen(
      (_) => promptSignal.cancel(),
    );
    final timer = Stopwatch()..start();
    var live = true, pinRequested = false, terminal = false;
    PasskeyErrorCode? stop;
    void halt(PasskeyErrorCode code) {
      stop ??= code;
      promptSignal.cancel();
      cancel(id);
    }

    Future<void> pin(Map<String, dynamic> event) async {
      Uint8List? bytes;
      try {
        final callback = interaction.requestPin;
        if (callback == null) {
          halt(PasskeyErrorCode.pinRequired);
          return;
        }
        final retries = event['attemptsRemaining'];
        if (retries is! int || retries < 1 || retries > 255) {
          halt(PasskeyErrorCode.backendFailure);
          return;
        }
        bytes = await callback(
          HardwarePinRequest(attemptsRemaining: retries),
          promptSignal,
        );
        if (!live || stop != null || cancellation.isCancelled) return;
        if (bytes == null) {
          halt(PasskeyErrorCode.cancelled);
          return;
        }
        // CTAP PIN input is UTF-8, 4..63 bytes, with no NUL. Never decode it into
        // an immutable Dart String. The authenticator enforces its PIN policy.
        if (bytes.length < 4 || bytes.length > 63 || bytes.contains(0)) {
          halt(PasskeyErrorCode.invalidRequest);
          return;
        }
        try {
          bytes[0] =
              bytes[0]; // Reject read-only views before submitting the PIN.
        } on UnsupportedError {
          halt(PasskeyErrorCode.invalidRequest);
          return;
        }
        final memory = calloc<Uint8>(bytes.length);
        try {
          memory.asTypedList(bytes.length).setAll(0, bytes);
          if (submitPin(id, memory, bytes.length) != 1) {
            halt(PasskeyErrorCode.backendFailure);
          }
        } finally {
          memory.asTypedList(bytes.length).fillRange(0, bytes.length, 0);
          calloc.free(memory);
        }
      } catch (_) {
        if (live) halt(PasskeyErrorCode.backendFailure);
      } finally {
        // Also runs when a consumer's PIN callback resolves after cancellation.
        try {
          bytes?.fillRange(0, bytes.length, 0);
        } on UnsupportedError {
          // A consumer violated the writable-buffer contract. Never let a late
          // callback escape as an unhandled asynchronous cleanup exception.
          if (live) halt(PasskeyErrorCode.invalidRequest);
        }
      }
    }

    try {
      while (true) {
        if (cancellation.isCancelled && stop == null) {
          halt(PasskeyErrorCode.cancelled);
        }
        if (timer.elapsed.inSeconds >= 125 && stop == null) {
          halt(PasskeyErrorCode.timeout);
        }
        // Keep cancelling until the worker drains; never reuse a live device.
        if (stop != null) cancel(id);
        final pointer = poll(id, size);
        if (pointer != nullptr) {
          try {
            final length = size.value;
            if (length < 12 || length > 65580) {
              throw const PasskeyException(PasskeyErrorCode.backendFailure);
            }
            final buffer = pointer.asTypedList(length);
            final header = ByteData.sublistView(buffer, 0, 12);
            final status = header.getUint32(0, Endian.little);
            final metadataLength = header.getUint32(4, Endian.little);
            final secretLength = header.getUint32(8, Endian.little);
            if (metadataLength > 65536 ||
                ![0, 32].contains(secretLength) ||
                length != 12 + metadataLength + secretLength ||
                status > 2 ||
                (status != 0 && secretLength != 0)) {
              throw const PasskeyException(PasskeyErrorCode.backendFailure);
            }
            if (status == 0 || status == 1) terminal = true;
            final event = jsonDecode(
              utf8.decode(
                Uint8List.sublistView(buffer, 12, 12 + metadataLength),
              ),
            );
            if (event is! Map<String, dynamic>) {
              throw const PasskeyException(PasskeyErrorCode.backendFailure);
            }
            if (status == 2) {
              if (stop != null) continue;
              if (event['event'] == 'pin' && !pinRequested) {
                pinRequested = true;
                unawaited(pin(event));
              } else if (event['event'] == 'touch') {
                interaction.onEvent?.call(HardwareEvent.touchRequired);
              } else if (event['event'] == 'presentKey') {
                interaction.onEvent?.call(HardwareEvent.presentKey);
              } else {
                halt(PasskeyErrorCode.backendFailure);
              }
            } else {
              if (stop != null) throw PasskeyException(stop!);
              if (status == 1) {
                final codes = PasskeyErrorCode.values.where(
                  (c) => c.name == event['error'],
                );
                throw PasskeyException(
                  codes.length == 1
                      ? codes.single
                      : PasskeyErrorCode.backendFailure,
                );
              }
              return NativeReply(
                event,
                Uint8List.fromList(
                  Uint8List.sublistView(buffer, 12 + metadataLength),
                ),
              );
            }
          } finally {
            release(pointer, size.value);
          }
        }
        if (timer.elapsed.inSeconds >= 135) {
          throw const PasskeyException(PasskeyErrorCode.backendFailure);
        }
        await Future<void>.delayed(const Duration(milliseconds: 25));
      }
    } catch (_) {
      // A malformed interaction or a consumer status exception must not strand
      // the process-wide native slot. Drain and erase every pending native reply.
      live = false;
      promptSignal.cancel();
      if (!terminal) {
        cancel(id);
        final draining = Stopwatch()..start();
        while (draining.elapsed.inSeconds < 10) {
          cancel(id);
          final pointer = poll(id, size);
          if (pointer != nullptr) {
            var finished = false;
            try {
              if (size.value >= 12 && size.value <= 65580) {
                final status = ByteData.sublistView(
                  pointer.asTypedList(12),
                ).getUint32(0, Endian.little);
                finished = status == 0 || status == 1;
              }
            } finally {
              release(pointer, size.value);
            }
            if (finished) break;
          }
          await Future<void>.delayed(const Duration(milliseconds: 25));
        }
      }
      rethrow;
    } finally {
      live = false;
      cancel(id); // no-op after the terminal frame has been consumed
      promptSignal.cancel();
      await subscription.cancel();
      calloc.free(size);
    }
  }

  @override
  Future<void> dispose() async {
    _disposed = true;
  }
}
