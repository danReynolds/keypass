import 'dart:async';

/// One-way cancellation signal. Create a new token for each user operation.
final class PasskeyCancellation {
  final StreamController<void> _events = StreamController<void>.broadcast(
    sync: true,
  );
  bool _cancelled = false;

  bool get isCancelled => _cancelled;

  /// Adapter integration: subscribe, then check [isCancelled] before starting.
  /// Cancel the subscription when the native request finishes.
  Stream<void> get onCancel => _events.stream;

  void cancel() {
    if (_cancelled) return;
    _cancelled = true;
    _events.add(null);
    unawaited(_events.close());
  }
}
