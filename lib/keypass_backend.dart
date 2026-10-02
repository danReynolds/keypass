/// Trusted adapter/test integration. Each factory invocation owns a fresh backend.
/// Backends are security components, not application authentication callbacks.
library;

export 'keypass.dart';
export 'src/backend.dart';
export 'src/models.dart'
    show PasskeyAvailability, PasskeyBinding, AuthenticatorState;
export 'src/hardware/interaction.dart' show HardwareInteraction;
export 'src/client.dart'
    show keypassWithBackendFactory, recordFromBinding, bindingFromRecord;
