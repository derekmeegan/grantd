/**
 * HostDO — one Durable Object per customer machine.
 *
 * It holds the host's public record, the signed public metadata of its grants,
 * and the hibernating WebSocket that lets a redemption reach a machine behind
 * NAT. It holds no secret of any kind, and every decision it makes is a routing
 * decision. The security decision happens on the customer's machine.
 *
 * Written defensively against its own operator: nothing here can construct a
 * redemption, extend an expiry in a way the host would honour, or change which
 * account a certificate is issued for. Those fields are covered by signatures
 * and MACs this object cannot produce.
 */

import { DurableObject } from "cloudflare:workers";
import { ERR, errorResponse, jsonResponse } from "../errors";
import { b64uDecode, b64uEncode } from "../crypto/encoding";
import { hostId as deriveHostId, verifyEd25519, GRANT_ID_RE } from "../crypto/ids";
import {
  canonicalGrant,
  canonicalHostConnect,
  canonicalHostRegistration,
  parseGrant,
  parseHostRegistration,
  parseRedemptionPayload,
  canonicalRedemptionSig,
  ParseError,
  SKEW_REGISTRATION,
  SKEW_REDEMPTION,
  withinSkew,
  type Grant,
  type HostRegistration,
} from "../protocol";
import type { Env } from "../env";

/** How long a redemption may wait for the host to answer. */
const REDEEM_TIMEOUT_MS = 20_000;

/** Cap on grants a single host may have published and unexpired at once. */
const MAX_PUBLISHED_GRANTS = 64;

/** Retention for redemption audit rows and expired grant metadata. */
const GRANT_RETENTION_S = 24 * 3600;
const REDEMPTION_RETENTION_S = 7 * 24 * 3600;

const ALARM_INTERVAL_MS = 60 * 60 * 1000;

/**
 * Per-host cap on redemption attempts that reach the rendezvous socket.
 *
 * This is the last line under the edge WAF and the Workers rate limiters, and
 * it is the only one with a consistent per-host view: every redemption for a
 * host lands in this one object, so a flood distributed across many IPs and
 * many grant ids still counts here. What it protects is the customer's machine,
 * which is woken once per forwarded attempt.
 *
 * A grant is single-use and a host holds a few dozen at most, so one attempt
 * per second sustained is far above any legitimate pattern.
 */
const MAX_REDEEM_ATTEMPTS_PER_WINDOW = 60;
const REDEEM_ATTEMPT_WINDOW_S = 60;

interface SocketMeta {
  host_id: string;
  protocol_version: number;
  connected_at: number;
}

interface Pending {
  resolve: (r: Response) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class HostDO extends DurableObject<Env> {
  /**
   * In-flight redemptions, keyed by request id. This is intentionally in
   * memory: the object stays alive for the duration of the HTTP request that
   * created the entry, and if it does not, the redeemer retries — an entry
   * lost to eviction costs a retry, never a wrong answer.
   */
  private pending = new Map<string, Pending>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.migrate();
    });
  }

  private get sql(): SqlStorage {
    return this.ctx.storage.sql;
  }

  private migrate(): void {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS host (
        guard               INTEGER PRIMARY KEY CHECK (guard = 1),
        host_id             TEXT NOT NULL,
        identity_public_key TEXT NOT NULL,
        ssh_ca_public_key   TEXT NOT NULL,
        hostname            TEXT NOT NULL,
        ssh_port            INTEGER NOT NULL,
        ssh_user            TEXT NOT NULL,
        protocol_version    INTEGER NOT NULL,
        created_at          INTEGER NOT NULL,
        last_seen_at        INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS grants (
        grant_id      TEXT PRIMARY KEY,
        signed_payload TEXT NOT NULL,
        host_signature TEXT NOT NULL,
        ssh_user      TEXT NOT NULL,
        created_at    INTEGER NOT NULL,
        expires_at    INTEGER NOT NULL,
        published_at  INTEGER NOT NULL,
        withdrawn_at  INTEGER
      );
      CREATE TABLE IF NOT EXISTS redemptions (
        request_id   TEXT PRIMARY KEY,
        grant_id     TEXT NOT NULL,
        agent_id     TEXT NOT NULL,
        key_fp       TEXT NOT NULL,
        requested_at INTEGER NOT NULL,
        completed_at INTEGER,
        status       TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS nonces (
        nonce   TEXT PRIMARY KEY,
        seen_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS redeem_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS redeem_attempts_at ON redeem_attempts (at);
    `);
  }

  private now(): number {
    return Math.floor(Date.now() / 1000);
  }

  // ------------------------------------------------------------------ routing

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const segments = url.pathname.split("/").filter(Boolean);

    try {
      // /do/<hostId>/...
      const rest = segments.slice(2);
      if (request.method === "PUT" && rest.length === 0) return await this.register(request);
      if (request.method === "GET" && rest.length === 0) return this.publicRecord();
      if (request.method === "GET" && rest[0] === "connect") return await this.rendezvous(request);
      if (rest[0] === "grants" && rest.length === 2) {
        if (request.method === "PUT") return await this.publishGrant(request, rest[1]);
        if (request.method === "GET") return this.grantRecord(rest[1]);
        if (request.method === "DELETE") return await this.withdrawGrant(request, rest[1]);
      }
      if (request.method === "POST" && rest[0] === "grants" && rest[2] === "redeem") {
        return await this.redeem(request, rest[1]);
      }
      return errorResponse(ERR.BAD_REQUEST, "no such host route", 404);
    } catch (e) {
      if (e instanceof ParseError) return errorResponse(e.code, e.message);
      console.error("hostdo error", { path: url.pathname, message: String(e) });
      return errorResponse(ERR.INTERNAL, "internal error");
    }
  }

  // ------------------------------------------------------------- registration

  private hostRow():
    | {
        host_id: string;
        identity_public_key: string;
        ssh_ca_public_key: string;
        hostname: string;
        ssh_port: number;
        ssh_user: string;
        protocol_version: number;
        created_at: number;
        last_seen_at: number;
      }
    | undefined {
    const rows = this.sql.exec("SELECT * FROM host WHERE guard = 1").toArray();
    return rows[0] as never;
  }

  private async register(request: Request): Promise<Response> {
    const body = (await request.json()) as Record<string, unknown>;
    const reg = parseHostRegistration(body.registration);
    const signature = decodeSig(body.signature);

    // The host ID is a hash of the identity key, so it is recomputed rather
    // than believed. Without this a caller could claim any host's identifier.
    const derived = await deriveHostId(reg.identity_public_key);
    if (derived !== reg.host_id) {
      return errorResponse(ERR.ID_MISMATCH, "host_id does not match identity_public_key");
    }

    const now = this.now();
    if (!withinSkew(now, reg.timestamp, SKEW_REGISTRATION)) {
      return errorResponse(ERR.STALE_TIMESTAMP, "registration timestamp is outside the allowed window");
    }
    if (!(await verifyEd25519(reg.identity_public_key, canonicalHostRegistration(reg), signature))) {
      return errorResponse(ERR.BAD_SIGNATURE, "registration signature does not verify");
    }
    if (this.seenNonce(reg.nonce, now)) {
      return errorResponse(ERR.REPLAYED_NONCE, "registration nonce has already been used");
    }

    const existing = this.hostRow();
    const encodedKey = b64uEncode(reg.identity_public_key);
    if (existing && existing.identity_public_key !== encodedKey) {
      // Unreachable while host_id is a hash of the key, but if that ever
      // changed this would be the moment a host got silently taken over.
      return errorResponse(ERR.ID_MISMATCH, "identity key for this host_id is immutable");
    }

    if (existing) {
      this.sql.exec(
        `UPDATE host SET ssh_ca_public_key = ?, hostname = ?, ssh_port = ?, ssh_user = ?,
                         protocol_version = ?, last_seen_at = ? WHERE guard = 1`,
        reg.ssh_ca_public_key,
        reg.hostname,
        Number(reg.ssh_port),
        reg.ssh_user,
        Number(reg.version),
        now,
      );
    } else {
      this.sql.exec(
        `INSERT INTO host (guard, host_id, identity_public_key, ssh_ca_public_key, hostname,
                           ssh_port, ssh_user, protocol_version, created_at, last_seen_at)
         VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        reg.host_id,
        encodedKey,
        reg.ssh_ca_public_key,
        reg.hostname,
        Number(reg.ssh_port),
        reg.ssh_user,
        Number(reg.version),
        now,
        now,
      );
    }
    await this.ensureAlarm();
    console.log(JSON.stringify({ event: "host.registered", host_id: reg.host_id }));
    return jsonResponse({ host_id: reg.host_id, registered: true, updated: Boolean(existing) }, existing ? 200 : 201);
  }

  private publicRecord(): Response {
    const h = this.hostRow();
    if (!h) return errorResponse(ERR.HOST_NOT_FOUND, "no such host");
    return jsonResponse({
      host_id: h.host_id,
      identity_public_key: h.identity_public_key,
      ssh_ca_public_key: h.ssh_ca_public_key,
      hostname: h.hostname,
      ssh_port: h.ssh_port,
      ssh_user: h.ssh_user,
      protocol_version: h.protocol_version,
      created_at: h.created_at,
      last_seen_at: h.last_seen_at,
      connected: this.ctx.getWebSockets().length > 0,
    });
  }

  // ---------------------------------------------------------------- rendezvous

  private async rendezvous(request: Request): Promise<Response> {
    const h = this.hostRow();
    if (!h) return errorResponse(ERR.HOST_NOT_FOUND, "register the host before connecting");
    if (request.headers.get("Upgrade") !== "websocket") {
      return errorResponse(ERR.BAD_REQUEST, "this endpoint requires a websocket upgrade", 426);
    }

    const tsHeader = request.headers.get("X-Grantd-Timestamp");
    const nonceHeader = request.headers.get("X-Grantd-Nonce");
    const sigHeader = request.headers.get("X-Grantd-Signature");
    if (!tsHeader || !nonceHeader || !sigHeader) {
      return errorResponse(ERR.BAD_REQUEST, "missing rendezvous authentication headers");
    }
    const ts = Number(tsHeader);
    if (!Number.isSafeInteger(ts) || ts < 0) {
      return errorResponse(ERR.BAD_REQUEST, "malformed timestamp header");
    }

    let nonce: Uint8Array;
    let signature: Uint8Array;
    try {
      nonce = b64uDecode(nonceHeader);
      signature = b64uDecode(sigHeader);
    } catch {
      return errorResponse(ERR.BAD_REQUEST, "malformed rendezvous headers");
    }
    if (nonce.length !== 16 || signature.length !== 64) {
      return errorResponse(ERR.BAD_REQUEST, "malformed rendezvous headers");
    }

    const now = this.now();
    if (!withinSkew(now, BigInt(ts), SKEW_REGISTRATION)) {
      return errorResponse(ERR.STALE_TIMESTAMP, "connect timestamp is outside the allowed window");
    }

    // The signature covers the path, and the path is reconstructed here rather
    // than read from the request: a signature captured for one endpoint must
    // not be replayable against another, and trusting a caller-supplied path
    // would let the caller choose what the signature appears to cover.
    const publicPath = `/v1/hosts/${h.host_id}/connect`;
    const message = canonicalHostConnect({
      version: BigInt(h.protocol_version),
      host_id: h.host_id,
      path: publicPath,
      timestamp: BigInt(ts),
      nonce,
    });
    const identity = b64uDecode(h.identity_public_key);
    if (!(await verifyEd25519(identity, message, signature))) {
      return errorResponse(ERR.BAD_SIGNATURE, "connect signature does not verify");
    }
    if (this.seenNonce(nonce, now)) {
      return errorResponse(ERR.REPLAYED_NONCE, "connect nonce has already been used");
    }

    // One machine, one rendezvous connection. A second authenticated connect
    // replaces the first rather than racing it.
    for (const old of this.ctx.getWebSockets()) {
      try {
        old.close(1012, "replaced by a newer connection");
      } catch {
        /* already gone */
      }
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const meta: SocketMeta = { host_id: h.host_id, protocol_version: h.protocol_version, connected_at: now };
    // Hibernation: Cloudflare keeps the socket attached while this object
    // sleeps, so thousands of idle hosts do not cost thousands of live objects.
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment(meta);

    this.sql.exec("UPDATE host SET last_seen_at = ? WHERE guard = 1", now);
    await this.ensureAlarm();
    server.send(JSON.stringify({ t: "hello", protocol_version: h.protocol_version }));
    console.log(JSON.stringify({ event: "host.connected", host_id: h.host_id }));

    return new Response(null, { status: 101, webSocket: client });
  }

  override async webSocketMessage(_ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== "string") return;
    if (message.length > 128 * 1024) return;

    let frame: { t?: unknown; id?: unknown; status?: unknown; body_b64?: unknown };
    try {
      frame = JSON.parse(message);
    } catch {
      return;
    }
    if (typeof frame.t !== "string") return;

    switch (frame.t) {
      case "pong":
        this.sql.exec("UPDATE host SET last_seen_at = ? WHERE guard = 1", this.now());
        return;
      case "redeem.response": {
        if (typeof frame.id !== "string") return;
        const waiter = this.pending.get(frame.id);
        if (!waiter) return; // late or unknown; drop it
        this.pending.delete(frame.id);
        clearTimeout(waiter.timer);
        const status = typeof frame.status === "number" ? frame.status : 502;
        this.sql.exec(
          "UPDATE redemptions SET completed_at = ?, status = ? WHERE request_id = ?",
          this.now(),
          status === 200 ? "issued" : "rejected",
          frame.id,
        );
        // The host's answer is relayed as opaque bytes. Parsing and
        // re-serializing it here would put this service in a position to
        // reshape the host's verdict, and would silently corrupt any 64-bit
        // value in it — a certificate serial does not survive a trip through
        // float64.
        let body: Uint8Array;
        try {
          body = b64uDecode(typeof frame.body_b64 === "string" ? frame.body_b64 : "");
        } catch {
          waiter.resolve(errorResponse(ERR.INTERNAL, "malformed response from host"));
          return;
        }
        waiter.resolve(
          new Response(body, {
            status,
            headers: { "content-type": "application/json; charset=utf-8" },
          }),
        );
        return;
      }
      default:
        // Unknown frames are dropped, never interpreted. The frame vocabulary
        // is fixed by the protocol and does not grow at runtime.
        return;
    }
  }

  override async webSocketClose(_ws: WebSocket, code: number): Promise<void> {
    console.log(JSON.stringify({ event: "host.disconnected", code }));
  }

  override async webSocketError(): Promise<void> {
    /* the runtime closes the socket for us */
  }

  // --------------------------------------------------------------- grants

  private async publishGrant(request: Request, grantId: string): Promise<Response> {
    const h = this.hostRow();
    if (!h) return errorResponse(ERR.HOST_NOT_FOUND, "no such host");

    const body = (await request.json()) as Record<string, unknown>;
    const grant = parseGrant(body.grant);
    const signature = decodeSig(body.signature);

    if (grant.grant_id !== grantId) {
      return errorResponse(ERR.BAD_REQUEST, "grant_id in body does not match the URL");
    }
    if (grant.host_id !== h.host_id) {
      return errorResponse(ERR.ID_MISMATCH, "grant is addressed to a different host");
    }
    // Only the host can publish a grant for itself. Nothing else about the
    // grant matters here: the service cannot validate the capability, only the
    // claim that this host made it.
    const identity = b64uDecode(h.identity_public_key);
    if (!(await verifyEd25519(identity, canonicalGrant(grant), signature))) {
      return errorResponse(ERR.BAD_SIGNATURE, "grant signature does not verify");
    }

    const now = this.now();
    if (Number(grant.expires_at) <= now) {
      return errorResponse(ERR.GRANT_EXPIRED, "grant is already expired");
    }

    const active = this.sql
      .exec("SELECT COUNT(*) AS n FROM grants WHERE expires_at > ? AND withdrawn_at IS NULL", now)
      .one() as { n: number };
    const alreadyKnown = this.sql
      .exec("SELECT COUNT(*) AS n FROM grants WHERE grant_id = ?", grantId)
      .one() as { n: number };
    if (active.n >= MAX_PUBLISHED_GRANTS && alreadyKnown.n === 0) {
      return errorResponse(ERR.TOO_MANY_GRANTS, "too many active grants for this host");
    }

    this.sql.exec(
      `INSERT INTO grants (grant_id, signed_payload, host_signature, ssh_user, created_at, expires_at, published_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(grant_id) DO UPDATE SET
         signed_payload = excluded.signed_payload,
         host_signature = excluded.host_signature,
         expires_at     = excluded.expires_at,
         published_at   = excluded.published_at`,
      grantId,
      JSON.stringify(serializeGrant(grant)),
      b64uEncode(signature),
      grant.ssh_user,
      Number(grant.created_at),
      Number(grant.expires_at),
      now,
    );
    await this.ensureAlarm();
    console.log(JSON.stringify({ event: "grant.published", host_id: h.host_id, grant_id: grantId }));
    return jsonResponse({ grant_id: grantId, published: true }, 201);
  }

  private grantRow(grantId: string):
    | { grant_id: string; signed_payload: string; host_signature: string; expires_at: number; withdrawn_at: number | null }
    | undefined {
    const rows = this.sql.exec("SELECT * FROM grants WHERE grant_id = ?", grantId).toArray();
    return rows[0] as never;
  }

  private grantRecord(grantId: string): Response {
    if (!GRANT_ID_RE.test(grantId)) return errorResponse(ERR.BAD_REQUEST, "malformed grant id");
    const row = this.grantRow(grantId);
    if (!row) return errorResponse(ERR.GRANT_NOT_FOUND, "no such grant");
    const h = this.hostRow();
    return jsonResponse({
      grant: JSON.parse(row.signed_payload),
      signature: row.host_signature,
      withdrawn: row.withdrawn_at !== null,
      host: h ? { hostname: h.hostname, ssh_port: h.ssh_port, ssh_user: h.ssh_user } : null,
      connected: this.ctx.getWebSockets().length > 0,
    });
  }

  private async withdrawGrant(request: Request, grantId: string): Promise<Response> {
    const h = this.hostRow();
    if (!h) return errorResponse(ERR.HOST_NOT_FOUND, "no such host");
    const row = this.grantRow(grantId);
    if (!row) return errorResponse(ERR.GRANT_NOT_FOUND, "no such grant");

    // Withdrawal is host-signed too. Removing public metadata is not a security
    // boundary — the host is authoritative — but an unauthenticated delete
    // would be a free denial-of-service against a customer's own grants.
    const body = (await request.json()) as Record<string, unknown>;
    const grant = parseGrant(body.grant);
    const signature = decodeSig(body.signature);
    if (grant.grant_id !== grantId || grant.host_id !== h.host_id) {
      return errorResponse(ERR.BAD_REQUEST, "withdrawal does not match this grant");
    }
    const identity = b64uDecode(h.identity_public_key);
    if (!(await verifyEd25519(identity, canonicalGrant(grant), signature))) {
      return errorResponse(ERR.BAD_SIGNATURE, "withdrawal signature does not verify");
    }
    this.sql.exec("UPDATE grants SET withdrawn_at = ? WHERE grant_id = ?", this.now(), grantId);
    return jsonResponse({ grant_id: grantId, withdrawn: true });
  }

  // ------------------------------------------------------------- redemption

  private async redeem(request: Request, grantId: string): Promise<Response> {
    const h = this.hostRow();
    if (!h) return errorResponse(ERR.HOST_NOT_FOUND, "no such host");

    const raw = await request.text();
    const body = JSON.parse(raw) as Record<string, unknown>;
    const payload = parseRedemptionPayload(body.payload);
    const agentSignature = decodeSig(body.agent_signature);

    if (payload.grant_id !== grantId) {
      return errorResponse(ERR.BAD_REQUEST, "grant_id in body does not match the URL");
    }
    if (payload.host_id !== h.host_id) {
      return errorResponse(ERR.ID_MISMATCH, "redemption is addressed to a different host");
    }

    const now = this.now();
    if (!withinSkew(now, payload.timestamp, SKEW_REDEMPTION)) {
      return errorResponse(ERR.STALE_TIMESTAMP, "redemption timestamp is outside the allowed window");
    }

    // Attribution only. The host re-verifies this, and the host is the one
    // whose opinion counts; checking here just keeps unattributable junk off
    // the rendezvous socket.
    if (!(await verifyEd25519(payload.agent_public_key, canonicalRedemptionSig(payload), agentSignature))) {
      return errorResponse(ERR.BAD_SIGNATURE, "agent signature does not verify");
    }

    const row = this.grantRow(grantId);
    if (!row) return errorResponse(ERR.GRANT_NOT_FOUND, "no such grant");
    if (row.withdrawn_at !== null) return errorResponse(ERR.GRANT_REVOKED, "grant was withdrawn");
    if (row.expires_at <= now) {
      // Advisory only; the host makes the authoritative expiry decision.
      return errorResponse(ERR.GRANT_EXPIRED, "grant has expired");
    }

    const sockets = this.ctx.getWebSockets();
    if (sockets.length === 0) {
      return errorResponse(ERR.HOST_OFFLINE, "the host is not currently connected");
    }

    // Counted here, immediately before the machine is woken, because that is
    // the resource being protected. Everything rejected above this line costs
    // the customer nothing.
    if (!this.recordRedeemAttempt(now)) {
      console.warn(
        JSON.stringify({ event: "host.redeem_throttled", host_id: h.host_id, grant_id: grantId }),
      );
      return errorResponse(ERR.RATE_LIMITED, "too many redemption attempts for this host");
    }

    const requestId = crypto.randomUUID();
    this.sql.exec(
      `INSERT INTO redemptions (request_id, grant_id, agent_id, key_fp, requested_at, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`,
      requestId,
      grantId,
      payload.agent_id,
      await sshKeyFingerprint(payload.ssh_public_key),
      now,
    );
    console.log(
      JSON.stringify({
        event: "grant.redemption_requested",
        host_id: h.host_id,
        grant_id: grantId,
        agent_id: payload.agent_id,
        request_id: requestId,
      }),
    );

    // The envelope is forwarded byte-for-byte, as opaque base64. Re-serializing
    // it would mean the host verifies bytes this service produced rather than
    // bytes the agent signed, which is exactly the substitution the design
    // forbids.
    const frame = JSON.stringify({
      t: "redeem.request",
      id: requestId,
      body_b64: b64uEncode(new TextEncoder().encode(raw)),
    });

    return await new Promise<Response>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(requestId);
        this.sql.exec(
          "UPDATE redemptions SET completed_at = ?, status = 'timeout' WHERE request_id = ?",
          this.now(),
          requestId,
        );
        resolve(errorResponse(ERR.HOST_TIMEOUT, "the host did not answer in time"));
      }, REDEEM_TIMEOUT_MS);

      this.pending.set(requestId, { resolve, timer });
      try {
        sockets[0].send(frame);
      } catch {
        clearTimeout(timer);
        this.pending.delete(requestId);
        resolve(errorResponse(ERR.HOST_OFFLINE, "the host connection dropped"));
      }
    });
  }

  // -------------------------------------------------------------- housekeeping

  private seenNonce(nonce: Uint8Array, now: number): boolean {
    const key = b64uEncode(nonce);
    this.sql.exec("DELETE FROM nonces WHERE seen_at < ?", now - SKEW_REGISTRATION * 4);
    const existing = this.sql.exec("SELECT COUNT(*) AS n FROM nonces WHERE nonce = ?", key).one() as {
      n: number;
    };
    if (existing.n > 0) return true;
    this.sql.exec("INSERT INTO nonces (nonce, seen_at) VALUES (?, ?)", key, now);
    return false;
  }

  /**
   * Records one forwarded redemption attempt and reports whether it is within
   * the per-host window. Returns false when the window is full, in which case
   * nothing is recorded and nothing is forwarded.
   */
  private recordRedeemAttempt(now: number): boolean {
    this.sql.exec("DELETE FROM redeem_attempts WHERE at < ?", now - REDEEM_ATTEMPT_WINDOW_S);
    const { n } = this.sql.exec("SELECT COUNT(*) AS n FROM redeem_attempts").one() as { n: number };
    if (n >= MAX_REDEEM_ATTEMPTS_PER_WINDOW) return false;
    this.sql.exec("INSERT INTO redeem_attempts (at) VALUES (?)", now);
    return true;
  }

  private async ensureAlarm(): Promise<void> {
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
    }
  }

  override async alarm(): Promise<void> {
    const now = this.now();
    this.sql.exec("DELETE FROM grants WHERE expires_at < ?", now - GRANT_RETENTION_S);
    this.sql.exec("DELETE FROM redemptions WHERE requested_at < ?", now - REDEMPTION_RETENTION_S);
    this.sql.exec("DELETE FROM nonces WHERE seen_at < ?", now - SKEW_REGISTRATION * 4);
    this.sql.exec("DELETE FROM redeem_attempts WHERE at < ?", now - REDEEM_ATTEMPT_WINDOW_S);
    await this.ctx.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
  }
}

function decodeSig(v: unknown): Uint8Array {
  if (typeof v !== "string") throw new ParseError(ERR.BAD_REQUEST, "signature must be a base64url string");
  let sig: Uint8Array;
  try {
    sig = b64uDecode(v);
  } catch {
    throw new ParseError(ERR.BAD_REQUEST, "signature must be base64url without padding");
  }
  if (sig.length !== 64) throw new ParseError(ERR.BAD_REQUEST, "signature must be 64 bytes");
  return sig;
}

function serializeGrant(g: Grant): Record<string, unknown> {
  return {
    version: Number(g.version),
    host_id: g.host_id,
    grant_id: g.grant_id,
    ssh_user: g.ssh_user,
    created_at: Number(g.created_at),
    expires_at: Number(g.expires_at),
  };
}

/** OpenSSH SHA256 fingerprint, for audit rows. Never the key itself. */
async function sshKeyFingerprint(line: string): Promise<string> {
  const b64 = line.split(" ")[1] ?? "";
  const bin = atob(b64);
  const blob = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) blob[i] = bin.charCodeAt(i);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", blob as BufferSource));
  let out = "";
  for (const b of digest) out += String.fromCharCode(b);
  return "SHA256:" + btoa(out).replace(/=+$/, "");
}

export type { HostRegistration };
