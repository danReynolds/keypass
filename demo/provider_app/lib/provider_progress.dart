import 'package:keypass/keypass_backend.dart';

enum ProviderCall { register, evaluate }

enum ProviderPhase { started, succeeded, failed }

/// Demo-only observation. Receives fixed operation/phase labels, never payloads.
final class ProgressBackend implements PasskeyBackend {
  ProgressBackend(this.inner, this.report);
  final PasskeyBackend inner;
  final Future<void> Function(ProviderCall, ProviderPhase) report;

  Future<void> _report(ProviderCall call, ProviderPhase phase) async {
    try {
      await report(call, phase);
    } catch (_) {
      // A diagnostic write must not retry, replace or fail a provider request.
    }
  }

  Future<T> _call<T>(ProviderCall call, Future<T> Function() action) async {
    await _report(call, ProviderPhase.started);
    try {
      final result = await action();
      await _report(call, ProviderPhase.succeeded);
      return result;
    } catch (_) {
      await _report(call, ProviderPhase.failed);
      rethrow;
    }
  }

  @override
  Future<PasskeyAvailability> availability({
    PasskeyCancellation? cancellation,
  }) => inner.availability(cancellation: cancellation);

  @override
  Future<PasskeyBinding> register(
    PasskeyRegistrationRequest request,
    PasskeyCancellation cancellation,
  ) =>
      _call(ProviderCall.register, () => inner.register(request, cancellation));

  @override
  Future<PasskeyAssertion> evaluate(
    PasskeyEvaluationRequest request,
    PasskeyCancellation cancellation,
  ) =>
      _call(ProviderCall.evaluate, () => inner.evaluate(request, cancellation));

  @override
  Future<void> dispose() => inner.dispose();
}
