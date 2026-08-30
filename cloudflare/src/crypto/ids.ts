/** Identifier derivation and Ed25519 verification — protocol/v1.md §3. */

import { base32Encode } from "./encoding";

export const PROTOCOL_VERSION = 1n;

export const HOST_ID_RE = /^h_[a-z2-7]{32}$/;
export const AGENT_ID_RE = /^a_[a-z2-7]{32}$/;
export const GRANT_ID_RE = /^g_[a-z2-7]{16}$/;
export const CHALLENGE_ID_RE = /^c_[a-z2-7]{26}$/;

/** SHA-256 truncated to the 20 bytes that base32 to exactly 32 characters. */
async function idMaterial(pub: Uint8Array): Promise<Uint8Array> {
  if (pub.length !== 32) throw new Error("public key must be 32 raw ed25519 bytes");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", pub as BufferSource));
  return digest.slice(0, 20);
}

export async function hostId(pub: Uint8Array): Promise<string> {
  return "h_" + base32Encode(await idMaterial(pub));
}

export async function agentId(pub: Uint8Array): Promise<string> {
  return "a_" + base32Encode(await idMaterial(pub));
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

/**
 * Verify an Ed25519 signature over canonical bytes.
 *
 * Returns false rather than throwing on malformed keys or signatures: a peer
 * sending garbage is an authentication failure, not an internal error, and
 * treating the two the same is how a 500 leaks the difference.
 */
export async function verifyEd25519(
  pub: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  if (pub.length !== 32 || signature.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("raw", pub as BufferSource, { name: "Ed25519" }, false, [
      "verify",
    ]);
    return await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      signature as BufferSource,
      message as BufferSource,
    );
  } catch {
    return false;
  }
}

/** Random identifier for a challenge: "c_" plus 16 random bytes in base32. */
export function newChallengeId(): string {
  const raw = new Uint8Array(16);
  crypto.getRandomValues(raw);
  return "c_" + base32Encode(raw);
}
