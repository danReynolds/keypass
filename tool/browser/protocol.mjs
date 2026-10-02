// Experimental peer of channel.dart. Browser WebCrypto; no third-party JS.
export const protocol = "keypass-browser-probe-v1";
const encoder = new TextEncoder();
export const encode = bytes =>
  btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
export function decode(value, length) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > 24000) throw new Error("Invalid encoding");
  const bytes = Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), c => c.charCodeAt(0));
  if ((length !== undefined && bytes.length !== length) || encode(bytes) !== value) throw new Error("Invalid encoding");
  return bytes;
}
const concat = (...parts) => {
  const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const part of parts) { result.set(part, i); i += part.length; }
  return result;
};
export function transcript(origin, domain, session, server, browser) {
  return JSON.stringify([protocol, origin, domain, session, encode(server), encode(browser)]);
}
export async function makePeer() {
  const pair = await crypto.subtle.generateKey("X25519", false, ["deriveBits"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { pair, publicKey };
}
export async function makeChannel(peer, remote, context, server = false) {
  const remoteKey = await crypto.subtle.importKey("raw", remote, "X25519", false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    {name: "X25519", public: remoteKey}, peer.pair.privateKey, 256));
  const salt = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(context)));
  let base;
  try {
    if (shared.every(b => b === 0)) throw new Error("Invalid peer");
    base = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits", "deriveKey"]);
  } finally { shared.fill(0); }
  const params = label => ({name: "HKDF", hash: "SHA-256", salt, info: encoder.encode(protocol + "/" + label)});
  let write = await crypto.subtle.deriveKey(params(server ? "s2b" : "b2s"), base,
    {name: "AES-GCM", length: 256}, false, ["encrypt"]);
  let read = await crypto.subtle.deriveKey(params(server ? "b2s" : "s2b"), base,
    {name: "AES-GCM", length: 256}, false, ["decrypt"]);
  const confirmation = new Uint8Array(await crypto.subtle.deriveBits(params("confirmation"), base, 128));
  const code = Array.from(confirmation, b => b.toString(16).padStart(2, "0")).join("").match(/.{4}/g).join(" ");
  confirmation.fill(0); base = undefined;
  let sent = 0, received = 0, closed = false, writing = false, reading = false;
  const nonce = sequence => {
    const bytes = new Uint8Array(12);
    new DataView(bytes.buffer).setUint32(8, sequence);
    return bytes;
  };
  const aad = (writing, seq) => concat(salt, encoder.encode("/" + (writing === server ? "s2b" : "b2s") + "/" + seq));
  return {
    code,
    async seal(clear) {
      if (closed || writing || sent >= 0xffffffff || clear.length > 16384) throw new Error("Channel unavailable");
      writing = true;
      const sequence = sent++;
      try {
        const encrypted = new Uint8Array(await crypto.subtle.encrypt(
          {name: "AES-GCM", iv: nonce(sequence), additionalData: aad(true, sequence)}, write, clear));
        if (closed) throw new Error("Channel closed");
        const header = new Uint8Array(4);
        new DataView(header.buffer).setUint32(0, sequence);
        return concat(header, encrypted);
      } finally { writing = false; }
    },
    async open(frame) {
      if (closed || reading || frame.length < 20 || frame.length > 16404) throw new Error("Invalid frame");
      const sequence = new DataView(frame.buffer, frame.byteOffset, 4).getUint32(0);
      if (sequence !== received) throw new Error("Unexpected sequence");
      reading = true;
      try {
        const clear = new Uint8Array(await crypto.subtle.decrypt(
          {name: "AES-GCM", iv: nonce(sequence), additionalData: aad(false, sequence)}, read, frame.subarray(4)));
        if (closed) { clear.fill(0); throw new Error("Channel closed"); }
        received++;
        return clear;
      } finally { reading = false; }
    },
    close() { closed = true; write = read = undefined; }
  };
}
