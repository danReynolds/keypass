import 'dart:convert';
import 'dart:typed_data';

/// Rejects duplicate JSON keys before they can be collapsed by jsonDecode.
/// Unknown client-data members are allowed, within the same resource bounds.
Map<String, Object?> parseClientData(Uint8List bytes) {
  if (bytes.isEmpty || bytes.length > 4096) _bad();
  final parser = _Json(utf8.decode(bytes, allowMalformed: false));
  final value = parser.read(0);
  parser.space();
  if (parser.at != parser.text.length || value is! Map<String, Object?>) _bad();
  return value;
}

final class _Json {
  _Json(this.text);
  final String text;
  int at = 0;
  int items = 0;
  void space() {
    while (at < text.length &&
        const [9, 10, 13, 32].contains(text.codeUnitAt(at))) {
      at++;
    }
  }

  bool take(String char) {
    space();
    if (at < text.length && text[at] == char) {
      at++;
      return true;
    }
    return false;
  }

  Object? read(int depth) {
    if (depth > 8 || ++items > 256) _bad();
    space();
    if (at >= text.length) _bad();
    if (text[at] == '"') return string();
    if (take('{')) {
      final result = <String, Object?>{};
      if (take('}')) return result;
      do {
        space();
        final key = string();
        if (result.containsKey(key) || !take(':')) _bad();
        result[key] = read(depth + 1);
        if (take('}')) return result;
      } while (take(','));
      return _bad();
    }
    if (take('[')) {
      final result = <Object?>[];
      if (take(']')) return result;
      do {
        result.add(read(depth + 1));
        if (take(']')) return result;
      } while (take(','));
      return _bad();
    }
    for (final entry in const {
      'true': true,
      'false': false,
      'null': null,
    }.entries) {
      if (text.startsWith(entry.key, at)) {
        at += entry.key.length;
        return entry.value;
      }
    }
    final number = RegExp(
      r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?',
    ).matchAsPrefix(text, at);
    if (number == null) _bad();
    at = number.end;
    final value = num.parse(number.group(0)!);
    if (!value.isFinite) _bad();
    return value;
  }

  String string() {
    if (at >= text.length || text[at] != '"') _bad();
    final start = at++;
    while (at < text.length) {
      final char = text[at++];
      if (char == '"') return jsonDecode(text.substring(start, at)) as String;
      if (char == r'\') at++;
    }
    return _bad();
  }
}

Never _bad() => throw const FormatException('Invalid WebAuthn client data');
