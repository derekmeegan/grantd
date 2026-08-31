/**
 * Agent admission control.
 *
 * This is a proof of work and nothing else. An earlier version also asked a
 * natural-language question, on the theory that it demonstrated liveness and
 * instruction-following. It was removed, because it was theater: the reference
 * solver shipped in this repository and handled every template, nothing ever
 * acted on the signal, and it cost a round trip and a template generator to
 * produce a number nobody read.
 *
 * What remains has a narrow, honest job. `/v1/agent-challenges` and
 * `/v1/agents` are unauthenticated endpoints that allocate Durable Objects, so
 * without a cost function anyone can make the service allocate without bound.
 * Twenty bits is about a second of CPU: free for one agent, expensive for a
 * million. It protects the bill, not the customer's machine.
 *
 * Registration is likewise an abuse control, not a security boundary — see
 * protocol/v1.md §11. It cannot be anything else in this architecture: the
 * signer is the only party whose opinion authorizes access, and it has no
 * network and no registry to consult.
 */

/** Leading zero bits of a digest, used to score proof of work. */
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

/** Verifies SHA-256(prefix || utf8(nonce)) has at least difficultyBits zeros. */
export async function verifyPow(
  prefix: Uint8Array,
  difficultyBits: number,
  nonce: string,
): Promise<boolean> {
  if (nonce.length === 0 || nonce.length > 64) return false;
  const nonceBytes = new TextEncoder().encode(nonce);
  const buf = new Uint8Array(prefix.length + nonceBytes.length);
  buf.set(prefix, 0);
  buf.set(nonceBytes, prefix.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf as BufferSource));
  return leadingZeroBits(digest) >= difficultyBits;
}
