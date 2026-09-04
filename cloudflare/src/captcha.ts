/**
 * Agent admission control: a proof of work.
 *
 * /v1/agent-challenges and /v1/agents are unauthenticated and allocate
 * Durable Objects. The proof of work puts a CPU cost on each registration.
 * It protects the bill. It is not a security boundary, see docs/whitepaper.md
 * section 11.
 */

/** Leading zero bits of a digest. Scores a proof of work. */
export function leadingZeroBits(digest: Uint8Array): number {
  let n = 0;
  for (const byte of digest) {
    if (byte === 0) {
      n += 8;
      continue;
    }
    for (let i = 7; i >= 0; i--) {
      if (byte & (1 << i)) return n;
      n++;
    }
    return n;
  }
  return n;
}

/** Longest nonce the protocol allows, in bytes. */
export const MAX_POW_NONCE_BYTES = 64;

/** Verifies that SHA-256(prefix || utf8(nonce)) has at least difficultyBits leading zeros. */
export async function verifyPow(
  prefix: Uint8Array,
  difficultyBits: number,
  nonce: string,
): Promise<boolean> {
  const nonceBytes = new TextEncoder().encode(nonce);
  if (nonceBytes.length === 0 || nonceBytes.length > MAX_POW_NONCE_BYTES) return false;
  const buf = new Uint8Array(prefix.length + nonceBytes.length);
  buf.set(prefix, 0);
  buf.set(nonceBytes, prefix.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf as BufferSource));
  return leadingZeroBits(digest) >= difficultyBits;
}
