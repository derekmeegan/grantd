/** Identifier derivation and Ed25519 verification, protocol/v1.md section 3. */

import { base32Encode } from "./encoding";

export const PROTOCOL_VERSION = 1n;

export const HOST_ID_RE = /^h_[a-z2-7]{32}$/;
export const AGENT_ID_RE = /^a_[a-z2-7]{32}$/;
export const GRANT_ID_RE = /^g_[a-z2-7]{16}$/;
export const CHALLENGE_ID_RE = /^c_[a-z2-7]{26}$/;

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

/** SHA-256 of the raw key, truncated to 20 bytes. 20 bytes base32 to 32 characters. */
async function idMaterial(pub: Uint8Array): Promise<Uint8Array> {
  if (pub.length !== 32) throw new Error("public key must be 32 raw ed25519 bytes");
  return (await sha256(pub)).slice(0, 20);
}

export async function hostId(pub: Uint8Array): Promise<string> {
  return "h_" + base32Encode(await idMaterial(pub));
}

export async function agentId(pub: Uint8Array): Promise<string> {
  return "a_" + base32Encode(await idMaterial(pub));
}

/**
 * Verify an Ed25519 signature over canonical bytes.
 *
 * Returns false instead of throwing on a malformed key or signature. A peer
 * that sends garbage is an authentication failure, not an internal error.
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

/** Random challenge identifier: "c_" plus 16 random bytes in base32. */
export function newChallengeId(): string {
  const raw = new Uint8Array(16);
  crypto.getRandomValues(raw);
  return "c_" + base32Encode(raw);
}
