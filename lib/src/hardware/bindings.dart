import 'dart:ffi';

// The asset ID is this library URI, registered by hook/build.dart. The ABI and
// binary PIN/secret boundary are unchanged; Dart supplies the library location.
@Native<Uint32 Function()>(symbol: 'keypass_hardware_abi_version')
external int hardwareAbiVersion();

@Native<Uint64 Function(Pointer<Uint8>, Uint32)>(
  symbol: 'keypass_hardware_start',
)
external int hardwareStart(Pointer<Uint8> request, int length);

@Native<Pointer<Uint8> Function(Uint64, Pointer<Uint32>)>(
  symbol: 'keypass_hardware_poll',
)
external Pointer<Uint8> hardwarePoll(int operation, Pointer<Uint32> size);

@Native<Uint32 Function(Uint64, Pointer<Uint8>, Uint32)>(
  symbol: 'keypass_hardware_pin',
)
external int hardwarePin(int operation, Pointer<Uint8> pin, int length);

@Native<Void Function(Uint64)>(symbol: 'keypass_hardware_cancel')
external void hardwareCancel(int operation);

@Native<Void Function(Pointer<Uint8>, Uint32)>(symbol: 'keypass_hardware_free')
external void hardwareFree(Pointer<Uint8> reply, int length);
