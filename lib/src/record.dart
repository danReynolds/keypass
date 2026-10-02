part of 'client.dart';

/// Immutable, nonsecret metadata required to recover a credential's secret.
/// Integrity-protect stored records; decoding does not establish authenticity.
/// v2 system and v3 hardware encodings preserve existing development records.
final class PasskeyRecord {
  PasskeyRecord._(this._binding);
  factory PasskeyRecord.fromJson(Map<String, Object?> json) =>
      PasskeyRecord._(PasskeyBinding.fromJson(json));
  final PasskeyBinding _binding;
  String get rpId => _binding.domain;
  PasskeyRoute get route => _binding.route;

  /// Stable identity of the credential and original PRF input.
  /// Independent of counters, backup state and USB/NFC transport hints.
  late final String id = base64Url
      .encode(
        SHA256Digest().process(
          Uint8List.fromList(
            utf8.encode(
              jsonEncode([
                'keypass-record-id-v1',
                route.name,
                rpId,
                base64Url.encode(_binding.credentialId),
                base64Url.encode(_binding.input),
              ]),
            ),
          ),
        ),
      )
      .replaceAll('=', '');

  Map<String, Object?> toJson() => _binding.toJson();
  @override
  String toString() => 'PasskeyRecord(${route.name})';
}
