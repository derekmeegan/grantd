/**
 * Test helpers that play the parts of a host and a visiting agent.
 *
 * They build messages the way the real Go implementations do: from canonical
 * bytes, with real Ed25519 signatures. The Worker tests then exercise
 * verification, not a mock of it.
 */

import { SELF } from "cloudflare:test";
import { b64uDecode, b64uEncode } from "../src/crypto/encoding";
import { leadingZeroBits } from "../src/captcha";
import { agentId as deriveAgentId, hostId as deriveHostId } from "../src/crypto/ids";
import {
  canonicalAgentRegistration,
  canonicalGrant,
  canonicalHostConnect,
  canonicalHostRegistration,
  canonicalRedemptionMac,
  canonicalRedemptionSig,
} from "../src/protocol";

export const ORIGIN = "https://grantd.test";

export interface Identity {
  publicKey: Uint8Array;
  privateKey: CryptoKey;
}

export async function newIdentity(): Promise<Identity> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
  return { publicKey: raw, privateKey: pair.privateKey };
}

export async function sign(id: Identity, message: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, id.privateKey, message as BufferSource),
  );
}

export function now(): number {
  return Math.floor(Date.now() / 1000);
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** A plausible ssh-ed25519 authorized_keys line built from real key bytes. */
export function sshLine(pub: Uint8Array): string {
  const prefix = new TextEncoder().encode("ssh-ed25519");
  const blob = new Uint8Array(4 + prefix.length + 4 + pub.length);
  const dv = new DataView(blob.buffer);
  dv.setUint32(0, prefix.length, false);
  blob.set(prefix, 4);
  dv.setUint32(4 + prefix.length, pub.length, false);
  blob.set(pub, 8 + prefix.length);
  let bin = "";
  for (const b of blob) bin += String.fromCharCode(b);
  return "ssh-ed25519 " + btoa(bin);
}

// ------------------------------------------------------------------- host

export class TestHost {
  constructor(
    readonly identity: Identity,
    readonly hostId: string,
    readonly caLine: string,
  ) {}

  static async create(): Promise<TestHost> {
    const identity = await newIdentity();
    const ca = await newIdentity();
    return new TestHost(identity, await deriveHostId(identity.publicKey), sshLine(ca.publicKey));
  }

  async registrationBody(
    overrides: Partial<{ hostname: string; ssh_port: number; ssh_user: string; timestamp: number }> = {},
  ): Promise<unknown> {
    const reg = {
      version: 1n,
      host_id: this.hostId,
      identity_public_key: this.identity.publicKey,
      ssh_ca_public_key: this.caLine,
      hostname: overrides.hostname ?? "box.example.com",
      ssh_port: BigInt(overrides.ssh_port ?? 22),
      ssh_user: overrides.ssh_user ?? "ubuntu",
      timestamp: BigInt(overrides.timestamp ?? now()),
      nonce: randomBytes(16),
    };
    const signature = await sign(this.identity, canonicalHostRegistration(reg));
    return {
      registration: {
        version: Number(reg.version),
        host_id: reg.host_id,
        identity_public_key: b64uEncode(reg.identity_public_key),
        ssh_ca_public_key: reg.ssh_ca_public_key,
        hostname: reg.hostname,
        ssh_port: Number(reg.ssh_port),
        ssh_user: reg.ssh_user,
        timestamp: Number(reg.timestamp),
        nonce: b64uEncode(reg.nonce),
      },
      signature: b64uEncode(signature),
    };
  }

  async register(): Promise<Response> {
    return await SELF.fetch(`${ORIGIN}/v1/hosts/${this.hostId}`, {
      method: "PUT",
      body: JSON.stringify(await this.registrationBody()),
      headers: { "content-type": "application/json" },
    });
  }

  async grantBody(grantId: string, ttl = 1800, createdAt = now()): Promise<unknown> {
    const grant = {
      version: 1n,
      host_id: this.hostId,
      grant_id: grantId,
      ssh_user: "ubuntu",
      created_at: BigInt(createdAt),
      expires_at: BigInt(createdAt + ttl),
    };
    const signature = await sign(this.identity, canonicalGrant(grant));
    return {
      grant: {
        version: 1,
        host_id: grant.host_id,
        grant_id: grant.grant_id,
        ssh_user: grant.ssh_user,
        created_at: Number(grant.created_at),
        expires_at: Number(grant.expires_at),
      },
      signature: b64uEncode(signature),
    };
  }

  async publishGrant(grantId: string, ttl = 1800): Promise<Response> {
    return await SELF.fetch(`${ORIGIN}/v1/hosts/${this.hostId}/grants/${grantId}`, {
      method: "PUT",
      body: JSON.stringify(await this.grantBody(grantId, ttl)),
      headers: { "content-type": "application/json" },
    });
  }

  /** Opens the rendezvous WebSocket the way the real daemon does. */
  async connect(timestampOverride?: number, nonceOverride?: Uint8Array): Promise<WebSocket> {
    const ts = timestampOverride ?? now();
    const nonce = nonceOverride ?? randomBytes(16);
    const path = `/v1/hosts/${this.hostId}/connect`;
    const signature = await sign(
      this.identity,
      canonicalHostConnect({
        version: 1n,
        host_id: this.hostId,
        path,
        timestamp: BigInt(ts),
        nonce,
      }),
    );
    const res = await SELF.fetch(`${ORIGIN}${path}`, {
      headers: {
        Upgrade: "websocket",
        "X-Grantd-Timestamp": String(ts),
        "X-Grantd-Nonce": b64uEncode(nonce),
        "X-Grantd-Signature": b64uEncode(signature),
      },
    });
    if (res.status !== 101 || !res.webSocket) {
      throw new Error(`rendezvous upgrade failed: ${res.status} ${await res.text()}`);
    }
    res.webSocket.accept();
    return res.webSocket;
  }
}

/** Finds a nonce whose SHA-256 with the prefix has enough leading zero bits. */
export async function solvePow(prefixB64: string, difficultyBits: number): Promise<string> {
  const prefix = b64uDecode(prefixB64);
  const enc = new TextEncoder();
  for (let i = 0; i < 1 << 26; i++) {
    const nonce = String(i);
    const nb = enc.encode(nonce);
    const buf = new Uint8Array(prefix.length + nb.length);
    buf.set(prefix, 0);
    buf.set(nb, prefix.length);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf as BufferSource));
    if (leadingZeroBits(digest) >= difficultyBits) return nonce;
  }
  throw new Error("could not solve the proof of work");
}

// ------------------------------------------------------------------ agent

export class TestAgent {
  constructor(
    readonly identity: Identity,
    readonly agentId: string,
    readonly sshKey: Identity,
  ) {}

  static async create(): Promise<TestAgent> {
    const identity = await newIdentity();
    const sshKey = await newIdentity();
    return new TestAgent(identity, await deriveAgentId(identity.publicKey), sshKey);
  }

  /** An agent that has completed registration, as a real redeemer must have. */
  static async registered(): Promise<TestAgent> {
    const a = await TestAgent.create();
    const res = await a.register();
    if (!res.ok) throw new Error(`registration failed: ${res.status} ${await res.text()}`);
    return a;
  }

  get sshPublicKeyLine(): string {
    return sshLine(this.sshKey.publicKey);
  }

  async redemptionBody(
    hostId: string,
    grantId: string,
    secret: Uint8Array,
    overrides: Partial<{ sshLine: string; timestamp: number; nonce: Uint8Array; agentId: string }> = {},
  ): Promise<Record<string, unknown>> {
    const payload = {
      version: 1n,
      host_id: hostId,
      grant_id: grantId,
      agent_id: overrides.agentId ?? this.agentId,
      agent_public_key: this.identity.publicKey,
      ssh_public_key: overrides.sshLine ?? this.sshPublicKeyLine,
      timestamp: BigInt(overrides.timestamp ?? now()),
      nonce: overrides.nonce ?? randomBytes(16),
    };
    const agentSignature = await sign(this.identity, canonicalRedemptionSig(payload));
    const key = await crypto.subtle.importKey(
      "raw",
      secret as BufferSource,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const proof = new Uint8Array(
      await crypto.subtle.sign("HMAC", key, canonicalRedemptionMac(payload) as BufferSource),
    );
    return {
      payload: {
        version: 1,
        host_id: payload.host_id,
        grant_id: payload.grant_id,
        agent_id: payload.agent_id,
        agent_public_key: b64uEncode(payload.agent_public_key),
        ssh_public_key: payload.ssh_public_key,
        timestamp: Number(payload.timestamp),
        nonce: b64uEncode(payload.nonce),
      },
      agent_signature: b64uEncode(agentSignature),
      proof: b64uEncode(proof),
    };
  }

  /**
   * Registers this identity for real: fetches a challenge, solves the proof
   * of work, and posts a signed registration. Redemption requires it.
   */
  async register(): Promise<Response> {
    const chRes = await SELF.fetch(`${ORIGIN}/v1/agent-challenges`, { method: "POST" });
    if (!chRes.ok) throw new Error(`challenge failed: ${chRes.status}`);
    const ch = (await chRes.json()) as {
      challenge_id: string;
      pow: { prefix: string; difficulty_bits: number };
    };
    const nonce = await solvePow(ch.pow.prefix, ch.pow.difficulty_bits);
    return await SELF.fetch(`${ORIGIN}/v1/agents`, {
      method: "POST",
      body: JSON.stringify(await this.registrationBody(ch.challenge_id, nonce)),
      headers: { "content-type": "application/json" },
    });
  }

  async registrationBody(challengeId: string, powNonce: string): Promise<unknown> {
    const reg = {
      version: 1n,
      agent_id: this.agentId,
      public_key: this.identity.publicKey,
      challenge_id: challengeId,
      pow_nonce: powNonce,
      timestamp: BigInt(now()),
    };
    const signature = await sign(this.identity, canonicalAgentRegistration(reg));
    return {
      registration: {
        version: 1,
        agent_id: reg.agent_id,
        public_key: b64uEncode(reg.public_key),
        challenge_id: reg.challenge_id,
        pow_nonce: reg.pow_nonce,
        timestamp: Number(reg.timestamp),
      },
      signature: b64uEncode(signature),
    };
  }
}

/** Random grant identifier in the protocol's shape. */
export function newGrantId(): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let out = "g_";
  const raw = randomBytes(16);
  for (const b of raw) out += alphabet[b % 32];
  return out;
}
