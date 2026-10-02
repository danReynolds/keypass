import 'dart:async';
import 'dart:io';

import 'package:keypass/keypass_backend.dart';
import 'package:keypass/src/native/backend.dart';
import 'channel.dart';
// Share the Flutter-free demo format without depending on its Flutter app.
// ignore: avoid_relative_lib_imports
import '../../demo/provider_app/lib/store.dart';

void send(Map<String, Object?> message) => stdout.add(demoPublicFrame(message));

final class HostTransport implements NativeTransport {
  int sequence = 0;
  final pending = <int, Completer<NativeReply>>{};
  bool closed = false;
  @override
  Future<NativeReply> exchange(
    Map<String, Object?> request,
    PasskeyCancellation cancellation,
  ) async {
    if (closed) throw const PasskeyException(PasskeyErrorCode.disposed);
    if (cancellation.isCancelled) {
      throw const PasskeyException(PasskeyErrorCode.cancelled);
    }
    final id = ++sequence;
    final completer = Completer<NativeReply>();
    pending[id] = completer;
    send({'kind': 'nativeRequest', 'id': id, 'request': request});
    final subscription = cancellation.onCancel.listen(
      (_) => send({'kind': 'nativeCancel', 'id': id}),
    );
    try {
      return await completer.future.timeout(
        const Duration(seconds: 130),
        onTimeout: () {
          send({'kind': 'nativeCancel', 'id': id});
          throw const PasskeyException(PasskeyErrorCode.timeout);
        },
      );
    } finally {
      pending.remove(id);
      await subscription.cancel();
    }
  }

  void receive(DemoFrame frame) {
    var transferred = false;
    try {
      final completer = pending.remove(frame.message['id']);
      if (completer == null || completer.isCompleted) return;
      final metadata = frame.message['metadata'];
      if (metadata is! Map<String, dynamic>) {
        completer.completeError(
          const PasskeyException(PasskeyErrorCode.backendFailure),
        );
      } else if (frame.message['status'] != 0) {
        final error = PasskeyErrorCode.values.where(
          (code) => code.name == metadata['error'],
        );
        completer.completeError(
          PasskeyException(
            error.length == 1 ? error.single : PasskeyErrorCode.backendFailure,
          ),
        );
      } else {
        completer.complete(NativeReply(metadata, frame.secret));
        transferred = true;
      }
    } finally {
      if (!transferred) frame.clear();
    }
  }

  @override
  Future<void> dispose() async {
    closed = true;
    for (final entry in pending.entries) {
      if (!entry.value.isCompleted) {
        entry.value.completeError(
          const PasskeyException(PasskeyErrorCode.cancelled),
        );
      }
    }
    pending.clear();
  }
}

// Each SDK operation owns its backend, but this IPC channel belongs to the
// worker process. Releasing an operation must leave the channel open for the
// next command. Only the worker's outer finally closes the underlying channel.
final class _BorrowedTransport implements NativeTransport {
  _BorrowedTransport(this.shared);
  final HostTransport shared;

  @override
  Future<NativeReply> exchange(
    Map<String, Object?> request,
    PasskeyCancellation cancellation,
  ) => shared.exchange(request, cancellation);

  @override
  Future<void> dispose() async {}
}

Future<void> main(List<String> args) async {
  if (args.length != 2) {
    exitCode = 64;
    return;
  }
  final domain = args[0];
  final configured = domain.isNotEmpty;
  // A placeholder permits a prompt-free host check before app setup. Credential
  // commands below are explicitly disabled until a real RP is configured.
  final rpId = configured ? domain : 'vault.example.com';
  final state = File(args[1]);
  final store = DemoStore(state);
  final transport = HostTransport();
  final passkeys = keypassWithBackendFactory(
    createBackend: () =>
        NativePasskeyBackend(_BorrowedTransport(transport), domain: rpId),
    rpId: rpId,
    displayName: 'Keypass Demo',
  );
  PasskeyCancellation? active;
  Future<void>? operation;
  bool exists() => state.existsSync();
  void report(String message, {String? code}) => send({
    'kind': 'status',
    'message': message,
    'code': code,
    'busy': active != null,
    'saved': exists(),
    'configured': configured,
  });
  Future<void> perform(String command) async {
    final signal = PasskeyCancellation();
    active = signal;
    try {
      switch (command) {
        case 'check':
          // Without identity, verify the presentation/transport path only. Never
          // request a credential for this deliberately unusable example domain.
          report('Checking the native macOS host and Dart connection…');
          final readiness = await passkeys.check();
          if (!readiness.canAttempt) throw PasskeyException(readiness.reason!);
          report(
            configured
                ? 'Native host and Dart SDK connected. Ready to attempt a passkey ceremony.'
                : 'Native host and Dart SDK connected. Configure a signed RP domain before creating a passkey.',
          );
        case 'enroll':
          if (!configured) {
            throw const PasskeyException(PasskeyErrorCode.configurationMissing);
          }
          if (exists()) {
            throw const PasskeyException(PasskeyErrorCode.invalidRequest);
          }
          report(
            'Create the test passkey, then approve the two verification prompts.',
          );
          await store.enroll(passkeys, cancellation: signal);
          report(
            'Passkey created. Both PRFs matched; the encrypted test marker is saved. Quit and reopen to check recovery.',
          );
        case 'unlock':
          if (!configured || !exists()) {
            throw const PasskeyException(
              PasskeyErrorCode.credentialUnavailable,
            );
          }
          report(
            'Approve the passkey prompt to decrypt the saved test marker.',
          );
          await store.unlock(passkeys, cancellation: signal);
          report(
            'Success: the saved marker decrypted. This passkey recovered the original encryption secret.',
          );
        default:
          throw const PasskeyException(PasskeyErrorCode.invalidRequest);
      }
    } on PasskeyException catch (error) {
      report('Operation stopped: ${error.code.name}.', code: error.code.name);
    } catch (_) {
      report('The demo could not complete the operation.', code: 'demoFailure');
    } finally {
      active = null;
      send({'kind': 'idle', 'saved': exists(), 'configured': configured});
    }
  }

  send({
    'kind': 'ready',
    'saved': exists(),
    'configured': configured,
    'statePath': state.path,
  });
  try {
    await for (final frame in readDemoFrames(stdin)) {
      final message = frame.message;
      if (message['kind'] == 'nativeResponse') {
        transport.receive(frame);
        continue;
      }
      frame.clear();
      if (message['kind'] != 'command') continue;
      if (message['command'] == 'cancel') {
        active?.cancel();
        continue;
      }
      if (active != null) continue;
      final command = message['command'];
      if (command is String) operation = perform(command);
    }
  } catch (_) {
    // IPC failures are redacted; never print a frame or provider response.
    exitCode = 1;
  } finally {
    active?.cancel();
    await transport.dispose();
    await operation;
  }
}
