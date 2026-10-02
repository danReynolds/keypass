part of 'client.dart';

/// Owned temporary secret and its new/updated recovery record.
/// Use try/finally and dispose even if encryption or persistence fails.
/// Successful completion transfers ownership; later cancellation cannot revoke it.
final class PasskeyResult {
  PasskeyResult._(this.record, Uint8List bytes) : _bytes = bytes;
  final PasskeyRecord record;
  Uint8List? _bytes;

  /// Borrowed read-only PRF material for the consumer's purpose-bound KDF.
  /// Throws after disposal. Previously obtained views then observe zeros.
  /// Consumer copies and derived keys remain the consumer's responsibility.
  Uint8List get secret {
    final bytes = _bytes;
    if (bytes == null) throw StateError('PasskeyResult has been disposed');
    return bytes.asUnmodifiableView();
  }

  /// Synchronous, idempotent cleanup of the owned secret buffer.
  /// Does not delete the passkey or persist metadata; the record remains usable.
  /// Does not promise erasure of every VM/OS temporary or consumer-owned copy.
  void dispose() {
    final bytes = _bytes;
    if (bytes == null) return;
    bytes.fillRange(0, bytes.length, 0);
    _bytes = null;
  }

  @override
  String toString() =>
      _bytes == null ? 'PasskeyResult(disposed)' : 'PasskeyResult(redacted)';
}

/// Prompt-free attempt readiness, not a guarantee of credential PRF support.
final class PasskeyReadiness {
  const PasskeyReadiness._(this.reason);
  final PasskeyErrorCode? reason;
  bool get canAttempt => reason == null;
}
