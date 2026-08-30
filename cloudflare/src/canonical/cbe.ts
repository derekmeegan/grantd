/**
 * grantd Canonical Binary Encoding (CBE) — protocol/v1.md §1.
 *
 * This is the TypeScript half of a deliberately duplicated implementation. The
 * Go signer and this Worker must produce identical bytes for identical
 * messages, and the only thing that keeps that true over time is that both are
 * written from the spec and both are checked against
 * protocol/test-vectors/v1.json.
 *
 * CBE is used instead of canonical JSON so that key ordering, duplicate keys,
 * Unicode escaping, number formatting and whitespace cannot become a
 * cross-implementation disagreement.
 */

export const TAG_STRING = 0x01;
export const TAG_U64 = 0x02;
export const TAG_BYTES = 0x03;
export const TAG_BOOL = 0x04;

/** Largest U64 the protocol permits, so signed-64-bit languages cannot differ. */
export const MAX_U64 = (1n << 63n) - 1n;

export type Field =
  | { name: string; tag: typeof TAG_STRING; value: string }
  | { name: string; tag: typeof TAG_U64; value: bigint }
  | { name: string; tag: typeof TAG_BYTES; value: Uint8Array }
  | { name: string; tag: typeof TAG_BOOL; value: boolean };

export const S = (name: string, value: string): Field => ({ name, tag: TAG_STRING, value });
export const U = (name: string, value: bigint | number): Field => ({
  name,
  tag: TAG_U64,
  value: typeof value === "bigint" ? value : BigInt(value),
});
export const B = (name: string, value: Uint8Array): Field => ({ name, tag: TAG_BYTES, value });
export const BL = (name: string, value: boolean): Field => ({ name, tag: TAG_BOOL, value });

export class CanonicalError extends Error {}

const NUL = String.fromCharCode(0);
const utf8 = new TextEncoder();
const utf8Decode = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Rejects strings that would not survive a round trip through UTF-8, and
 * strings containing U+0000.
 *
 * A lone surrogate encodes to U+FFFD rather than throwing, which would silently
 * change the signed bytes without anyone noticing, so the check is a re-decode
 * and comparison rather than a scan for suspicious characters.
 */
function encodeString(name: string, s: string): Uint8Array {
  if (s.includes(NUL)) {
    throw new CanonicalError(`canonical: field ${name} contains U+0000`);
  }
  const bytes = utf8.encode(s);
  let round: string;
  try {
    round = utf8Decode.decode(bytes);
  } catch {
    throw new CanonicalError(`canonical: field ${name} is not valid UTF-8`);
  }
  if (round !== s) {
    throw new CanonicalError(`canonical: field ${name} is not valid UTF-8`);
  }
  return bytes;
}

class Writer {
  private chunks: Uint8Array[] = [];
  private len = 0;

  push(b: Uint8Array): void {
    this.chunks.push(b);
    this.len += b.length;
  }

  u32(n: number): void {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n, false);
    this.push(b);
  }

  lp(b: Uint8Array): void {
    this.u32(b.length);
    this.push(b);
  }

  byte(n: number): void {
    this.push(new Uint8Array([n]));
  }

  finish(): Uint8Array {
    const out = new Uint8Array(this.len);
    let off = 0;
    for (const c of this.chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  }
}

/**
 * CBE(context, fields) =
 *      LP(utf8(context))
 *   || u32be(len(fields))
 *   || for each field: LP(utf8(name)) || tag || LP(value)
 *
 * Field order is the order given, never sorted. Names are covered so that a
 * value cannot be shifted into another field's position.
 */
export function encode(context: string, fields: Field[]): Uint8Array {
  if (context.length === 0) throw new CanonicalError("canonical: context is empty");
  const w = new Writer();
  w.lp(encodeString("<context>", context));
  w.u32(fields.length);

  for (const f of fields) {
    if (!f.name) throw new CanonicalError("canonical: field name is empty");
    w.lp(encodeString(f.name, f.name));
    w.byte(f.tag);
    switch (f.tag) {
      case TAG_STRING:
        w.lp(encodeString(f.name, f.value));
        break;
      case TAG_U64: {
        if (f.value < 0n || f.value > MAX_U64) {
          throw new CanonicalError(`canonical: field ${f.name} is out of u64 range`);
        }
        const b = new Uint8Array(8);
        new DataView(b.buffer).setBigUint64(0, f.value, false);
        w.lp(b);
        break;
      }
      case TAG_BYTES:
        w.lp(f.value);
        break;
      case TAG_BOOL:
        w.lp(new Uint8Array([f.value ? 1 : 0]));
        break;
      default:
        throw new CanonicalError("canonical: unknown type tag");
    }
  }
  return w.finish();
}
