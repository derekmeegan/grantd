/**
 * grantd v1 message schemas for the coordination service.
 *
 * The Worker's job is to route, and to refuse to route obvious garbage. It
 * verifies host signatures because it must know which host a connection belongs
 * to, and it verifies agent signatures because attribution and rate limiting
 * depend on them. It does not, and cannot, verify a redemption proof: that
 * requires the grant secret, which by design it never has.
 */

import { encode, S, U, B, type Field } from "./canonical/cbe";
import { b64uDecode } from "./crypto/encoding";
import { AGENT_ID_RE, GRANT_ID_RE, HOST_ID_RE, PROTOCOL_VERSION } from "./crypto/ids";

export const CTX_HOST_REGISTER = "grantd/v1/host-register";
export const CTX_HOST_CONNECT = "grantd/v1/host-connect";
export const CTX_GRANT = "grantd/v1/grant";
export const CTX_REDEMPTION_SIG = "grantd/v1/redemption-agent-sig";
export const CTX_REDEMPTION_MAC = "grantd/v1/redemption-proof";
export const CTX_AGENT_REGISTER = "grantd/v1/agent-register";

export const SKEW_REGISTRATION = 300;
export const SKEW_REDEMPTION = 120;
export const MAX_GRANT_TTL = 8 * 3600;
export const MIN_GRANT_TTL = 60;

export const MAX_REQUEST_BYTES = 16 * 1024;
export const MAX_SSH_PUBKEY_BYTES = 1024;
export const MAX_ANSWER_BYTES = 256;
export const MAX_POW_NONCE_BYTES = 64;
export const MAX_HOSTNAME_BYTES = 253;
export const MAX_USERNAME_BYTES = 32;

/** A parse failure carrying the protocol error code the client should see. */
export class ParseError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

function bad(message: string): never {
  throw new ParseError("BAD_REQUEST", message);
}

// ------------------------------------------------------------------ helpers

function requireObject(v: unknown, what: string): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) bad(`${what} must be an object`);
  return v as Record<string, unknown>;
}

function str(o: Record<string, unknown>, key: string, max: number): string {
  const v = o[key];
  if (typeof v !== "string") bad(`${key} must be a string`);
  if (v.length > max) bad(`${key} exceeds ${max} bytes`);
  return v;
}

/**
 * Integers arrive as JSON numbers and are turned into bigints for CBE. A
 * non-integer, a float, or anything past 2^53 is rejected rather than rounded,
 * because a value that survives rounding differently in two implementations is
 * a signature mismatch waiting to happen.
 */
function int(o: Record<string, unknown>, key: string): bigint {
  const v = o[key];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
    bad(`${key} must be a non-negative integer`);
  }
  return BigInt(v);
}

function bytes(o: Record<string, unknown>, key: string, exactLen?: number): Uint8Array {
  const v = o[key];
  if (typeof v !== "string") bad(`${key} must be a base64url string`);
  let decoded: Uint8Array;
  try {
    decoded = b64uDecode(v);
  } catch {
    return bad(`${key} must be base64url without padding`);
  }
  if (exactLen !== undefined && decoded.length !== exactLen) {
    bad(`${key} must be ${exactLen} bytes`);
  }
  return decoded;
}

function checkVersion(v: bigint): void {
  if (v !== PROTOCOL_VERSION) {
    throw new ParseError("UNSUPPORTED_VERSION", `protocol version ${v} is not supported`);
  }
}

// -------------------------------------------------------------- host register

export interface HostRegistration {
  version: bigint;
  host_id: string;
  identity_public_key: Uint8Array;
  ssh_ca_public_key: string;
  hostname: string;
  ssh_port: bigint;
  ssh_user: string;
  timestamp: bigint;
  nonce: Uint8Array;
}

export function parseHostRegistration(raw: unknown): HostRegistration {
  const o = requireObject(raw, "registration");
  const m: HostRegistration = {
    version: int(o, "version"),
    host_id: str(o, "host_id", 64),
    identity_public_key: bytes(o, "identity_public_key", 32),
    ssh_ca_public_key: str(o, "ssh_ca_public_key", MAX_SSH_PUBKEY_BYTES),
    hostname: str(o, "hostname", MAX_HOSTNAME_BYTES),
    ssh_port: int(o, "ssh_port"),
    ssh_user: str(o, "ssh_user", MAX_USERNAME_BYTES),
    timestamp: int(o, "timestamp"),
    nonce: bytes(o, "nonce", 16),
  };
  checkVersion(m.version);
  if (!HOST_ID_RE.test(m.host_id)) bad("malformed host_id");
  if (m.ssh_port === 0n || m.ssh_port > 65535n) bad("ssh_port out of range");
  if (m.ssh_user === "root") bad("root may not be enrolled");
  if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(m.ssh_user)) bad("malformed ssh_user");
  return m;
}

export function hostRegistrationFields(m: HostRegistration): Field[] {
  return [
    U("version", m.version),
    S("host_id", m.host_id),
    B("identity_public_key", m.identity_public_key),
    S("ssh_ca_public_key", m.ssh_ca_public_key),
    S("hostname", m.hostname),
    U("ssh_port", m.ssh_port),
    S("ssh_user", m.ssh_user),
    U("timestamp", m.timestamp),
    B("nonce", m.nonce),
  ];
}

export const canonicalHostRegistration = (m: HostRegistration): Uint8Array =>
  encode(CTX_HOST_REGISTER, hostRegistrationFields(m));

// --------------------------------------------------------------- host connect

export interface HostConnect {
  version: bigint;
  host_id: string;
  path: string;
  timestamp: bigint;
  nonce: Uint8Array;
}

export const canonicalHostConnect = (m: HostConnect): Uint8Array =>
  encode(CTX_HOST_CONNECT, [
    U("version", m.version),
    S("host_id", m.host_id),
    S("path", m.path),
    U("timestamp", m.timestamp),
    B("nonce", m.nonce),
  ]);

// ---------------------------------------------------------------------- grant

export interface Grant {
  version: bigint;
  host_id: string;
  grant_id: string;
  ssh_user: string;
  created_at: bigint;
  expires_at: bigint;
}

export function parseGrant(raw: unknown): Grant {
  const o = requireObject(raw, "grant");
  const m: Grant = {
    version: int(o, "version"),
    host_id: str(o, "host_id", 64),
    grant_id: str(o, "grant_id", 64),
    ssh_user: str(o, "ssh_user", MAX_USERNAME_BYTES),
    created_at: int(o, "created_at"),
    expires_at: int(o, "expires_at"),
  };
  checkVersion(m.version);
  if (!HOST_ID_RE.test(m.host_id)) bad("malformed host_id");
  if (!GRANT_ID_RE.test(m.grant_id)) bad("malformed grant_id");
  if (m.expires_at <= m.created_at) bad("expires_at must be after created_at");
  const ttl = m.expires_at - m.created_at;
  if (ttl < BigInt(MIN_GRANT_TTL)) bad("grant ttl is below the minimum");
  if (ttl > BigInt(MAX_GRANT_TTL)) bad("grant ttl exceeds the maximum");
  return m;
}

export const canonicalGrant = (m: Grant): Uint8Array =>
  encode(CTX_GRANT, [
    U("version", m.version),
    S("host_id", m.host_id),
    S("grant_id", m.grant_id),
    S("ssh_user", m.ssh_user),
    U("created_at", m.created_at),
    U("expires_at", m.expires_at),
  ]);

// ----------------------------------------------------------------- redemption

export interface RedemptionPayload {
  version: bigint;
  host_id: string;
  grant_id: string;
  agent_id: string;
  agent_public_key: Uint8Array;
  ssh_public_key: string;
  timestamp: bigint;
  nonce: Uint8Array;
}

export function parseRedemptionPayload(raw: unknown): RedemptionPayload {
  const o = requireObject(raw, "payload");
  const m: RedemptionPayload = {
    version: int(o, "version"),
    host_id: str(o, "host_id", 64),
    grant_id: str(o, "grant_id", 64),
    agent_id: str(o, "agent_id", 64),
    agent_public_key: bytes(o, "agent_public_key", 32),
    ssh_public_key: str(o, "ssh_public_key", MAX_SSH_PUBKEY_BYTES),
    timestamp: int(o, "timestamp"),
    nonce: bytes(o, "nonce", 16),
  };
  checkVersion(m.version);
  if (!HOST_ID_RE.test(m.host_id)) bad("malformed host_id");
  if (!GRANT_ID_RE.test(m.grant_id)) bad("malformed grant_id");
  if (!AGENT_ID_RE.test(m.agent_id)) bad("malformed agent_id");
  // Strict authorized_keys shape. The exact string is what the host's MAC
  // covers, so it is validated rather than normalized.
  if (!/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$/.test(m.ssh_public_key)) {
    bad("ssh_public_key must be a two-field ssh-ed25519 authorized_keys line");
  }
  return m;
}

function redemptionFields(m: RedemptionPayload): Field[] {
  return [
    U("version", m.version),
    S("host_id", m.host_id),
    S("grant_id", m.grant_id),
    S("agent_id", m.agent_id),
    B("agent_public_key", m.agent_public_key),
    S("ssh_public_key", m.ssh_public_key),
    U("timestamp", m.timestamp),
    B("nonce", m.nonce),
  ];
}

export const canonicalRedemptionSig = (m: RedemptionPayload): Uint8Array =>
  encode(CTX_REDEMPTION_SIG, redemptionFields(m));

export const canonicalRedemptionMac = (m: RedemptionPayload): Uint8Array =>
  encode(CTX_REDEMPTION_MAC, redemptionFields(m));

// ------------------------------------------------------------- agent register

export interface AgentRegistration {
  version: bigint;
  agent_id: string;
  public_key: Uint8Array;
  challenge_id: string;
  answer: string;
  pow_nonce: string;
  timestamp: bigint;
}

export function parseAgentRegistration(raw: unknown): AgentRegistration {
  const o = requireObject(raw, "registration");
  const m: AgentRegistration = {
    version: int(o, "version"),
    agent_id: str(o, "agent_id", 64),
    public_key: bytes(o, "public_key", 32),
    challenge_id: str(o, "challenge_id", 64),
    answer: str(o, "answer", MAX_ANSWER_BYTES),
    pow_nonce: str(o, "pow_nonce", MAX_POW_NONCE_BYTES),
    timestamp: int(o, "timestamp"),
  };
  checkVersion(m.version);
  if (!AGENT_ID_RE.test(m.agent_id)) bad("malformed agent_id");
  return m;
}

export const canonicalAgentRegistration = (m: AgentRegistration): Uint8Array =>
  encode(CTX_AGENT_REGISTER, [
    U("version", m.version),
    S("agent_id", m.agent_id),
    B("public_key", m.public_key),
    S("challenge_id", m.challenge_id),
    S("answer", m.answer),
    S("pow_nonce", m.pow_nonce),
    U("timestamp", m.timestamp),
  ]);

// ------------------------------------------------------------------ envelopes

export interface SignedEnvelope<T> {
  message: T;
  signature: Uint8Array;
}

export function parseSignature(raw: Record<string, unknown>, key = "signature"): Uint8Array {
  return bytes(raw, key, 64);
}

export interface RedemptionRequest {
  payload: RedemptionPayload;
  agent_signature: Uint8Array;
  proof: Uint8Array;
}

export function parseRedemptionRequest(raw: unknown): RedemptionRequest {
  const o = requireObject(raw, "body");
  return {
    payload: parseRedemptionPayload(o.payload),
    agent_signature: bytes(o, "agent_signature", 64),
    proof: bytes(o, "proof", 32),
  };
}

export function withinSkew(now: number, ts: bigint, skew: number): boolean {
  const t = Number(ts);
  return Math.abs(now - t) <= skew;
}
