/**
 * grantd v1 message schemas for the coordination service.
 *
 * The Worker routes messages and refuses obvious garbage. It verifies host
 * signatures to know which host a request belongs to. It verifies agent
 * signatures for attribution and rate limiting. It cannot verify a
 * redemption proof, because it never holds the grant secret.
 */

import { encode, S, U, B, type Field } from "./canonical/cbe";
import { b64StdDecode, b64StdEncodeNoPad, b64uDecode, b64uEncode } from "./crypto/encoding";
import { AGENT_ID_RE, GRANT_ID_RE, HOST_ID_RE, PROTOCOL_VERSION, sha256 } from "./crypto/ids";
import { MAX_POW_NONCE_BYTES } from "./captcha";

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
export const MAX_HOSTNAME_BYTES = 253;
export const MAX_USERNAME_BYTES = 32;

/** A parse failure that carries the protocol error code the client must see. */
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

/**
 * Parses a JSON object from raw text. Returns undefined for invalid JSON or
 * a non-object. Callers must not log the parser's error message. It can
 * contain a slice of the input, and a redemption body carries a proof.
 */
export function parseJsonObject(raw: string): Record<string, unknown> | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
  return parsed as Record<string, unknown>;
}

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
 * Reads a JSON number as a bigint for CBE. Rejects floats, negatives and
 * anything past 2^53. Two implementations can round such values differently.
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

/** Reads a 64-byte Ed25519 signature from an envelope field. */
export function parseSignature(raw: Record<string, unknown>, key = "signature"): Uint8Array {
  return bytes(raw, key, 64);
}

// ------------------------------------------------------------ ssh public key

const SSH_ED25519 = "ssh-ed25519";
/** u32 type length || "ssh-ed25519" || u32 key length || 32 key bytes. */
const SSH_ED25519_BLOB_LEN = 4 + SSH_ED25519.length + 4 + 32;

/**
 * Parses an authorized_keys line and returns the wire blob. v1 accepts only
 * ssh-ed25519 with exactly two fields and no comment. The exact string is
 * what the host's MAC covers, so nothing is normalized.
 */
export function parseSshEd25519Line(line: string): Uint8Array {
  const parts = line.split(" ");
  if (parts.length !== 2 || parts[0] !== SSH_ED25519) {
    bad("ssh_public_key must be a two-field ssh-ed25519 authorized_keys line");
  }
  let blob: Uint8Array;
  try {
    blob = b64StdDecode(parts[1]);
  } catch {
    return bad("ssh_public_key blob is not valid base64");
  }
  if (blob.length !== SSH_ED25519_BLOB_LEN) bad("ssh_public_key blob has the wrong length");
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const type = new TextDecoder().decode(blob.subarray(4, 4 + SSH_ED25519.length));
  if (dv.getUint32(0) !== SSH_ED25519.length || type !== SSH_ED25519) {
    bad("ssh_public_key blob is not ssh-ed25519");
  }
  if (dv.getUint32(4 + SSH_ED25519.length) !== 32) bad("ssh_public_key blob has a bad key length");
  return blob;
}

/** OpenSSH SHA256 fingerprint of a key line. Used for audit rows, never the key itself. */
export async function sshKeyFingerprint(line: string): Promise<string> {
  return "SHA256:" + b64StdEncodeNoPad(await sha256(parseSshEd25519Line(line)));
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

/** The JSON form of a registration, as a host sends it and as the public record echoes it. */
export function serializeHostRegistration(m: HostRegistration): Record<string, unknown> {
  return {
    version: Number(m.version),
    host_id: m.host_id,
    identity_public_key: b64uEncode(m.identity_public_key),
    ssh_ca_public_key: m.ssh_ca_public_key,
    hostname: m.hostname,
    ssh_port: Number(m.ssh_port),
    ssh_user: m.ssh_user,
    timestamp: Number(m.timestamp),
    nonce: b64uEncode(m.nonce),
  };
}

export const canonicalHostRegistration = (m: HostRegistration): Uint8Array =>
  encode(CTX_HOST_REGISTER, [
    U("version", m.version),
    S("host_id", m.host_id),
    B("identity_public_key", m.identity_public_key),
    S("ssh_ca_public_key", m.ssh_ca_public_key),
    S("hostname", m.hostname),
    U("ssh_port", m.ssh_port),
    S("ssh_user", m.ssh_user),
    U("timestamp", m.timestamp),
    B("nonce", m.nonce),
  ]);

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

export function serializeGrant(g: Grant): Record<string, unknown> {
  return {
    version: Number(g.version),
    host_id: g.host_id,
    grant_id: g.grant_id,
    ssh_user: g.ssh_user,
    created_at: Number(g.created_at),
    expires_at: Number(g.expires_at),
  };
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
  parseSshEd25519Line(m.ssh_public_key);
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

// ------------------------------------------------------------- agent register

export interface AgentRegistration {
  version: bigint;
  agent_id: string;
  public_key: Uint8Array;
  challenge_id: string;
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
    S("pow_nonce", m.pow_nonce),
    U("timestamp", m.timestamp),
  ]);

// ----------------------------------------------------------------------- time

export function withinSkew(now: number, ts: bigint, skew: number): boolean {
  const t = Number(ts);
  return Math.abs(now - t) <= skew;
}
