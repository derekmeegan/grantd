/**
 * Cross-language conformance.
 *
 * The Go implementation produced these fixtures. The TypeScript one checks
 * them here. Neither implementation is the reference. Both are written from
 * protocol/v1.md and both must reproduce the same bytes.
 */

import { describe, expect, it } from "vitest";
import vectors from "../../protocol/test-vectors/v1.json";
import { b64uDecode, b64uEncode, hexDecode, hexEncode } from "../src/crypto/encoding";
import { agentId, hostId, verifyEd25519 } from "../src/crypto/ids";
import {
  CTX_AGENT_REGISTER,
  CTX_GRANT,
  CTX_HOST_CONNECT,
  CTX_HOST_REGISTER,
  CTX_REDEMPTION_MAC,
  CTX_REDEMPTION_SIG,
  canonicalAgentRegistration,
  canonicalGrant,
  canonicalHostConnect,
  canonicalHostRegistration,
  canonicalRedemptionMac,
  canonicalRedemptionSig,
} from "../src/protocol";

type Vector = {
  name: string;
  context: string;
  message: Record<string, unknown>;
  canonical_hex: string;
  signature_hex?: string;
  signing_key_seed_hex?: string;
  mac_hex?: string;
  mac_key_hex?: string;
};

const bundle = vectors as unknown as {
  keys: Record<string, string>;
  identifiers: Record<string, string>;
  capability: Record<string, string>;
  vectors: Vector[];
};

/** base64url-decodes a field of the JSON message, as a real peer does. */
function b(v: unknown): Uint8Array {
  return b64uDecode(String(v));
}

function n(v: unknown): bigint {
  return BigInt(v as number);
}

function s(v: unknown): string {
  return v as string;
}

function canonicalFor(v: Vector): Uint8Array {
  const m = v.message;
  switch (v.context) {
    case CTX_HOST_REGISTER:
      return canonicalHostRegistration({
        version: n(m.version),
        host_id: s(m.host_id),
        identity_public_key: b(m.identity_public_key),
        ssh_ca_public_key: s(m.ssh_ca_public_key),
        hostname: s(m.hostname),
        ssh_port: n(m.ssh_port),
        ssh_user: s(m.ssh_user),
        timestamp: n(m.timestamp),
        nonce: b(m.nonce),
      });
    case CTX_HOST_CONNECT:
      return canonicalHostConnect({
        version: n(m.version),
        host_id: s(m.host_id),
        path: s(m.path),
        timestamp: n(m.timestamp),
        nonce: b(m.nonce),
      });
    case CTX_GRANT:
      return canonicalGrant({
        version: n(m.version),
        host_id: s(m.host_id),
        grant_id: s(m.grant_id),
        ssh_user: s(m.ssh_user),
        created_at: n(m.created_at),
        expires_at: n(m.expires_at),
      });
    case CTX_REDEMPTION_SIG:
    case CTX_REDEMPTION_MAC: {
      const payload = {
        version: n(m.version),
        host_id: s(m.host_id),
        grant_id: s(m.grant_id),
        agent_id: s(m.agent_id),
        agent_public_key: b(m.agent_public_key),
        ssh_public_key: s(m.ssh_public_key),
        timestamp: n(m.timestamp),
        nonce: b(m.nonce),
      };
      return v.context === CTX_REDEMPTION_SIG
        ? canonicalRedemptionSig(payload)
        : canonicalRedemptionMac(payload);
    }
    case CTX_AGENT_REGISTER:
      return canonicalAgentRegistration({
        version: n(m.version),
        agent_id: s(m.agent_id),
        public_key: b(m.public_key),
        challenge_id: s(m.challenge_id),
        pow_nonce: s(m.pow_nonce),
        timestamp: n(m.timestamp),
      });
    default:
      throw new Error(`unknown context ${v.context}`);
  }
}

/** Derives the Ed25519 public key from a raw seed, via a PKCS#8 wrapper. */
async function publicFromSeed(seed: Uint8Array): Promise<Uint8Array> {
  const pkcs8 = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ...seed,
  ]);
  const key = await crypto.subtle.importKey("pkcs8", pkcs8 as BufferSource, { name: "Ed25519" }, true, [
    "sign",
  ]);
  const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
  return b64uDecode(jwk.x as string);
}

describe("cross-language protocol vectors", () => {
  it("has vectors to check", () => {
    expect(bundle.vectors.length).toBeGreaterThan(0);
  });

  for (const v of bundle.vectors) {
    it(`canonicalizes ${v.name} to the same bytes as Go`, () => {
      expect(hexEncode(canonicalFor(v))).toBe(v.canonical_hex);
    });
  }

  for (const v of bundle.vectors.filter((x) => x.signature_hex)) {
    it(`verifies the Go-produced signature for ${v.name}`, async () => {
      const pub = await publicFromSeed(hexDecode(v.signing_key_seed_hex!));
      const ok = await verifyEd25519(pub, canonicalFor(v), hexDecode(v.signature_hex!));
      expect(ok).toBe(true);
    });

    it(`rejects a tampered signature for ${v.name}`, async () => {
      const pub = await publicFromSeed(hexDecode(v.signing_key_seed_hex!));
      const sig = hexDecode(v.signature_hex!);
      sig[0] ^= 0xff;
      expect(await verifyEd25519(pub, canonicalFor(v), sig)).toBe(false);
    });
  }

  for (const v of bundle.vectors.filter((x) => x.mac_hex)) {
    it(`reproduces the Go-produced HMAC for ${v.name}`, async () => {
      const key = await crypto.subtle.importKey(
        "raw",
        hexDecode(v.mac_key_hex!) as BufferSource,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
      );
      const mac = new Uint8Array(
        await crypto.subtle.sign("HMAC", key, canonicalFor(v) as BufferSource),
      );
      expect(hexEncode(mac)).toBe(v.mac_hex);
    });
  }

  it("derives the same host and agent identifiers as Go", async () => {
    expect(await hostId(hexDecode(bundle.keys.host_identity_pub_hex))).toBe(
      bundle.identifiers.host_id,
    );
    expect(await agentId(hexDecode(bundle.keys.agent_identity_pub_hex))).toBe(
      bundle.identifiers.agent_id,
    );
  });

  it("encodes the capability secret the same way as Go", () => {
    expect(b64uEncode(hexDecode(bundle.keys.grant_secret_hex))).toBe(
      bundle.capability.secret_b64url,
    );
  });

  it("gives the redemption signature and proof distinct canonical bytes", () => {
    const sig = bundle.vectors.find((v) => v.context === CTX_REDEMPTION_SIG)!;
    const mac = bundle.vectors.find((v) => v.context === CTX_REDEMPTION_MAC)!;
    expect(sig.canonical_hex).not.toBe(mac.canonical_hex);
  });
});
