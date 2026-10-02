import 'dart:convert';
import 'dart:typed_data';

/// Deliberately narrow CBOR profile for WebAuthn: definite lengths, scalar map
/// keys, no tags/floats, bounded nesting/items, no duplicate keys or trailing data.
/// This is a parser, not a general-purpose CBOR codec.
final class BoundedCbor {
  BoundedCbor(this.bytes, {this.offset = 0}) {
    if (bytes.length > 16384 || offset < 0 || offset > bytes.length) _bad();
  }

  final Uint8List bytes;
  int offset;
  int _items = 0;

  Object? read([int depth = 0]) {
    if (depth > 8 || ++_items > 256) _bad();
    final head = _byte();
    final major = head >> 5;
    final additional = head & 31;
    if (major == 7) {
      return switch (additional) {
        20 => false,
        21 => true,
        22 => null,
        _ => _bad(),
      };
    }
    final length = _length(additional);
    switch (major) {
      case 0:
        return length;
      case 1:
        return -1 - length;
      case 2:
      case 3:
        if (length > bytes.length - offset) _bad();
        final value = Uint8List.sublistView(bytes, offset, offset + length);
        offset += length;
        return major == 2 ? value : utf8.decode(value, allowMalformed: false);
      case 4:
        if (length > 128) _bad();
        return List<Object?>.generate(length, (_) => read(depth + 1));
      case 5:
        if (length > 64) _bad();
        final map = <Object, Object?>{};
        for (var i = 0; i < length; i++) {
          final key = read(depth + 1);
          if ((key is! int && key is! String) || map.containsKey(key)) _bad();
          map[key!] = read(depth + 1);
        }
        return map;
      default:
        return _bad();
    }
  }

  Object? readAll() {
    final value = read();
    if (offset != bytes.length) _bad();
    return value;
  }

  int _length(int additional) {
    if (additional < 24) return additional;
    final count = switch (additional) {
      24 => 1,
      25 => 2,
      26 => 4,
      _ => _bad(),
    };
    var value = 0;
    for (var i = 0; i < count; i++) {
      value = value * 256 + _byte();
    }
    if (value <
        (count == 1
            ? 24
            : count == 2
            ? 256
            : 65536)) {
      _bad();
    }
    return value;
  }

  int _byte() {
    if (offset >= bytes.length) _bad();
    return bytes[offset++];
  }
}

Never _bad() => throw const FormatException('Invalid WebAuthn CBOR');
