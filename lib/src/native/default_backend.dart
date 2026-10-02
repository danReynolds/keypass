import '../backend.dart';
import '../hardware/interaction.dart';
import 'backend.dart';
import 'ffi_transport.dart';
import '../hardware/backend.dart';
import '../hardware/ffi_transport.dart';

PasskeyBackend hardwareBackend(
  String namespace,
  HardwareInteraction interaction,
) => HardwarePasskeyBackend(
  HardwareFfiTransport(interaction),
  namespace: namespace,
  interaction: interaction,
);

PasskeyBackend defaultBackend(String domain) =>
    NativePasskeyBackend(FfiNativeTransport(), domain: domain);
