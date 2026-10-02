// Synthetic fixture encoder; never loaded by the browser helper.
const utf8 = s => new TextEncoder().encode(s);
export function cbor(value) {
  const head = (major, n) => n < 24 ? [major * 32 + n] : n < 256 ? [major * 32 + 24, n] : [major * 32 + 25, n >> 8, n & 255];
  if (value instanceof Uint8Array) return new Uint8Array([...head(2, value.length), ...value]);
  if (typeof value === 'string') { const b = utf8(value); return new Uint8Array([...head(3, b.length), ...b]); }
  if (typeof value === 'number') return new Uint8Array(value >= 0 ? head(0, value) : head(1, -1-value));
  if (typeof value === 'boolean') return new Uint8Array([value ? 245 : 244]);
  const entries = value instanceof Map ? [...value] : Object.entries(value);
  return new Uint8Array([...head(5, entries.length), ...entries.flatMap(([k,v]) => [...cbor(k), ...cbor(v)])]);
}
