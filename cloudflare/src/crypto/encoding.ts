/**
 * Byte encodings the protocol uses. Every decoder here is exact. A decoder
 * that accepts two spellings of one value lets a peer change bytes without
 * changing meaning.
 */

const B32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

/** RFC 4648 base32, lowercase alphabet, no padding. */
export function base32Encode(bytes: Uint8Array): string {
  let out = "";
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += B32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

/** base64url without padding. This is the only binary-in-JSON encoding in v1. */
export function b64uEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export class DecodeError extends Error {}

/**
 * Strict base64url decode. Rejects padding, the standard alphabet, and any
 * input that does not re-encode to itself.
 */
export function b64uDecode(s: string): Uint8Array {
  if (typeof s !== "string" || s.length === 0) {
    throw new DecodeError("expected base64url without padding");
  }
  if (!/^[A-Za-z0-9_-]+$/.test(s)) {
    throw new DecodeError("expected base64url without padding");
  }
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  let bin: string;
  try {
    bin = atob(padded);
  } catch {
    throw new DecodeError("expected base64url without padding");
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (b64uEncode(out) !== s) {
    throw new DecodeError("base64url input is not canonical");
  }
  return out;
}

/** Standard base64 decode, as used in an authorized_keys line. Throws DecodeError. */
export function b64StdDecode(s: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s) || s.length % 4 !== 0) {
    throw new DecodeError("expected standard base64");
  }
  let bin: string;
  try {
    bin = atob(s);
  } catch {
    throw new DecodeError("expected standard base64");
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Standard base64 encode with padding stripped, as in an OpenSSH fingerprint. */
export function b64StdEncodeNoPad(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/=+$/, "");
}

export function hexEncode(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function hexDecode(s: string): Uint8Array {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) {
    throw new DecodeError("expected hex");
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
