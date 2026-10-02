import '../backend.dart';
import '../hardware/interaction.dart';

PasskeyBackend defaultBackend(String domain) =>
    const UnavailablePasskeyBackend();

PasskeyBackend hardwareBackend(
  String namespace,
  HardwareInteraction interaction,
) => const UnavailablePasskeyBackend();
