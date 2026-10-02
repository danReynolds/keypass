import 'dart:typed_data';
import '../cancellation.dart';

/// A connection offered by this operation, not an enrolled credential.
/// Return the exact offered object; stale options from other operations fail.
final class HardwareConnection {
  HardwareConnection._({required this.name, this.transport});
  final String name;

  /// Null when the native discovery API cannot establish a transport.
  final HardwareTransport? transport;
  @override
  String toString() => 'HardwareConnection';
}

// Adapter-internal constructor, not exported by the consumer library.
HardwareConnection hardwareConnection({
  required String name,
  HardwareTransport? transport,
}) => HardwareConnection._(name: name, transport: transport);

enum HardwareTransport { usb, nfc }

/// Informational events. These never prove that authentication succeeded.
enum HardwareEvent {
  touchRequired,

  /// Hold the key near the NFC reader until the operation completes.
  presentKey,
}

final class HardwarePinRequest {
  const HardwarePinRequest({required this.attemptsRemaining});
  final int attemptsRemaining;
}

/// Return owned, writable UTF-8 PIN bytes or null to cancel. Keypass clears the
/// bytes, including late replies after cancellation. Close UI on cancellation.
/// PINs are never automatically retried.
typedef HardwarePinPrompt =
    Future<Uint8List?> Function(
      HardwarePinRequest request,
      PasskeyCancellation cancellation,
    );

/// Return an offered connection from this invocation, or null to cancel.
typedef HardwareConnectionPicker =
    Future<HardwareConnection?> Function(
      List<HardwareConnection> connections,
      PasskeyCancellation cancellation,
    );

/// Adapter-internal bundle. Public callers use Keypass.hardware's arguments.
final class HardwareInteraction {
  const HardwareInteraction({
    this.requestPin,
    this.selectConnection,
    this.onEvent,
  });
  final HardwarePinPrompt? requestPin;
  final HardwareConnectionPicker? selectConnection;
  final void Function(HardwareEvent)? onEvent;
}
