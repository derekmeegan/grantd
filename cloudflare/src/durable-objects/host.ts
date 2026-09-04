/**
 * HostDO, one Durable Object per customer machine.
 *
 * It holds the host's public record, the signed metadata of its grants, and
 * the hibernating WebSocket to the machine. It holds no secret. Every
 * decision here is a routing decision. The customer's machine makes the
 * security decision.
 */

import { DurableObject } from "cloudflare:workers";
import { ERR, errorResponse, jsonResponse } from "../errors";
import { b64uDecode, b64uEncode } from "../crypto/encoding";
import { agentId as deriveAgentId, hostId as deriveHostId, verifyEd25519 } from "../crypto/ids";
import {
  canonicalGrant,
  canonicalHostConnect,
  canonicalHostRegistration,
  canonicalRedemptionSig,
  parseGrant,
  parseHostRegistration,
  parseJsonObject,
  parseRedemptionRequest,
  parseSignature,
  ParseError,
  serializeGrant,
  serializeHostRegistration,
  sshKeyFingerprint,
  SKEW_REGISTRATION,
  SKEW_REDEMPTION,
  withinSkew,
} from "../protocol";
import { CLIENT_IP_HEADER, dnsConfig, hostRecordName, syncHostRecord } from "../dns";
import type { AgentRecord } from "./agent";
import type { Env } from "../env";

/** How long a redemption waits for the host to answer. */
const REDEEM_TIMEOUT_MS = 20_000;

/** Cap on unexpired grants one host can have published at once. */
const MAX_PUBLISHED_GRANTS = 64;

/** Retention for expired grant metadata and redemption audit rows. */
const GRANT_RETENTION_S = 24 * 3600;
const REDEMPTION_RETENTION_S = 7 * 24 * 3600;

const ALARM_INTERVAL_MS = 60 * 60 * 1000;

/**
 * Per-host cap on redemption attempts that reach the socket. Every
 * redemption for a host lands in this one object, so a flood spread over
 * many IPs and many grant ids still counts here.
 */
const MAX_REDEEM_ATTEMPTS_PER_WINDOW = 60;
const REDEEM_ATTEMPT_WINDOW_S = 60;

/** Largest text frame accepted from a host. */
const MAX_FRAME_CHARS = 128 * 1024;

/** WebSocket readyState for an open socket. */
const WS_OPEN = 1;

/** Attached to each accepted socket. Survives hibernation. */
interface SocketMeta {
  host_id: string;
  connected_at_ms: number;
}

interface Pending {
  resolve: (r: Response) => void;
  timer: ReturnType<typeof setTimeout>;
  /** connected_at_ms of the socket the request went out on. */
  socketId: number;
}

type HostRow = {
  host_id: string;
  identity_public_key: string;
  ssh_ca_public_key: string;
  hostname: string;
  ssh_port: number;
  ssh_user: string;
  protocol_version: number;
  created_at: number;
  last_seen_at: number;
  registration_json: string | null;
  registration_signature: string | null;
  dns_name: string | null;
  dns_ip: string | null;
};

type GrantRow = {
  grant_id: string;
  signed_payload: string;
  host_signature: string;
  expires_at: number;
};

interface HostFrame {
  t?: unknown;
  id?: unknown;
  status?: unknown;
  body_b64?: unknown;
}

export class HostDO extends DurableObject<Env> {
  /**
   * In-flight redemptions by request id. In memory on purpose: the object
   * stays awake while the HTTP request that created the entry is open.
   */
  private pending = new Map<string, Pending>();

  private schemaReady = false;

  private get sql(): SqlStorage {
    return this.ctx.storage.sql;
  }

  /** True when the host table exists. Reads sqlite_master only, which persists nothing. */
  private hasSchema(): boolean {
    if (this.schemaReady) return true;
    const rows = this.sql
      .exec("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'host'")
      .toArray();
    return rows.length > 0;
  }

  /**
   * Creates or upgrades the schema. DDL is a storage write and persists the
   * object, so read paths must not call this on an unregistered host.
   */
  private migrate(): void {
    if (this.schemaReady) return;
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
        last_seen_at        INTEGER NOT NULL,
        registration_json      TEXT,
        registration_signature TEXT,
        dns_name               TEXT,
        dns_ip                 TEXT
      );
      CREATE TABLE IF NOT EXISTS grants (
        grant_id      TEXT PRIMARY KEY,
        signed_payload TEXT NOT NULL,
        host_signature TEXT NOT NULL,
        ssh_user      TEXT NOT NULL,
        created_at    INTEGER NOT NULL,
        expires_at    INTEGER NOT NULL,
        published_at  INTEGER NOT NULL
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
    // Objects created before these columns existed get them here.
    const columns = new Set(
      this.sql.exec("PRAGMA table_info(host)").toArray().map((r) => r.name as string),
    );
    if (!columns.has("registration_json")) {
      this.sql.exec("ALTER TABLE host ADD COLUMN registration_json TEXT");
    }
    if (!columns.has("registration_signature")) {
      this.sql.exec("ALTER TABLE host ADD COLUMN registration_signature TEXT");
    }
    if (!columns.has("dns_name")) {
      this.sql.exec("ALTER TABLE host ADD COLUMN dns_name TEXT");
    }
    if (!columns.has("dns_ip")) {
      this.sql.exec("ALTER TABLE host ADD COLUMN dns_ip TEXT");
    }
    this.schemaReady = true;
  }

  private now(): number {
    return Math.floor(Date.now() / 1000);
  }

  // ------------------------------------------------------------------ routing

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    // /host/<hostId>/...
    const rest = url.pathname.split("/").filter(Boolean).slice(2);

    try {
      if (request.method === "PUT" && rest.length === 0) return await this.register(request);
      if (request.method === "GET" && rest.length === 0) return this.publicRecord();
      if (request.method === "GET" && rest[0] === "connect") return await this.rendezvous(request);
      if (rest[0] === "grants" && rest.length === 2) {
        if (request.method === "PUT") return await this.publishGrant(request, rest[1]);
        if (request.method === "GET") return this.grantRecord(rest[1]);
      }
      if (request.method === "POST" && rest[0] === "grants" && rest.length === 3 && rest[2] === "redeem") {
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

  /** The host record, or undefined when this host was never registered. */
  private hostRow(): HostRow | undefined {
    if (!this.hasSchema()) return undefined;
    this.migrate();
    return this.sql.exec<HostRow>("SELECT * FROM host WHERE guard = 1").toArray()[0];
  }

  private async register(request: Request): Promise<Response> {
    const body = (await request.json()) as Record<string, unknown>;
    const reg = parseHostRegistration(body.registration);
    const signature = parseSignature(body);

    // The ID is a hash of the key. Recompute it instead of trusting it.
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

    // A valid signature has been seen. Only now does the object persist.
    this.migrate();
    if (this.seenNonce(reg.nonce, now)) {
      return errorResponse(ERR.REPLAYED_NONCE, "registration nonce has already been used");
    }

    const existing = this.hostRow();
    const encodedKey = b64uEncode(reg.identity_public_key);
    if (existing && existing.identity_public_key !== encodedKey) {
      // Unreachable while host_id is a hash of the key. Kept as a guard.
      return errorResponse(ERR.ID_MISMATCH, "identity key for this host_id is immutable");
    }

    const registrationJson = JSON.stringify(serializeHostRegistration(reg));
    const registrationSignature = b64uEncode(signature);
    if (existing) {
      this.sql.exec(
        `UPDATE host SET ssh_ca_public_key = ?, hostname = ?, ssh_port = ?, ssh_user = ?,
                         protocol_version = ?, last_seen_at = ?,
                         registration_json = ?, registration_signature = ?
         WHERE guard = 1`,
        reg.ssh_ca_public_key,
        reg.hostname,
        Number(reg.ssh_port),
        reg.ssh_user,
        Number(reg.version),
        now,
        registrationJson,
        registrationSignature,
      );
    } else {
      this.sql.exec(
        `INSERT INTO host (guard, host_id, identity_public_key, ssh_ca_public_key, hostname,
                           ssh_port, ssh_user, protocol_version, created_at, last_seen_at,
                           registration_json, registration_signature)
         VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        reg.host_id,
        encodedKey,
        reg.ssh_ca_public_key,
        reg.hostname,
        Number(reg.ssh_port),
        reg.ssh_user,
        Number(reg.version),
        now,
        now,
        registrationJson,
        registrationSignature,
      );
    }
    await this.ensureAlarm();
    console.log(JSON.stringify({ event: "host.registered", host_id: reg.host_id }));

    // Awaited, unlike the reconnect path: the installer prints the name it
    // got, so enrolling should not report a name that does not resolve yet.
    // A DNS failure never fails the registration.
    const dnsName = await this.syncDns(
      reg.host_id,
      reg.hostname,
      request.headers.get(CLIENT_IP_HEADER),
    );
    return jsonResponse(
      { host_id: reg.host_id, registered: true, updated: Boolean(existing), dns_name: dnsName },
      existing ? 200 : 201,
    );
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
      connected: this.liveSocket() !== undefined,
      // The name this service manages for the host, when it has one.
      dns_name: h.dns_name,
      // The last accepted registration, so a visitor can verify the record itself.
      registration: h.registration_json ? JSON.parse(h.registration_json) : null,
      signature: h.registration_signature,
    });
  }

  // ---------------------------------------------------------------- rendezvous

  private async rendezvous(request: Request): Promise<Response> {
    const h = this.hostRow();
    if (!h) return errorResponse(ERR.HOST_NOT_FOUND, "register the host before connecting");
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
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

    // The path is rebuilt here, not read from the request. A signature for
    // one endpoint must not verify against another.
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

    // One machine, one connection. A new authenticated connect replaces the old one.
    for (const old of this.ctx.getWebSockets()) {
      try {
        old.close(1012, "replaced by a newer connection");
      } catch {
        /* already gone */
      }
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const meta: SocketMeta = { host_id: h.host_id, connected_at_ms: Date.now() };
    // Hibernation keeps the socket attached while this object sleeps.
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment(meta);

    this.sql.exec("UPDATE host SET last_seen_at = ? WHERE guard = 1", now);
    await this.ensureAlarm();

    // A machine on a dynamic address moves between reconnects, and this is
    // the only authenticated signal that it has. Not awaited: the host is
    // waiting on this upgrade, and the record is stale either way until the
    // call lands.
    const clientIp = request.headers.get(CLIENT_IP_HEADER);
    if (clientIp && clientIp !== h.dns_ip) {
      this.ctx.waitUntil(this.syncDns(h.host_id, h.hostname, clientIp));
    }

    server.send(JSON.stringify({ t: "hello", protocol_version: h.protocol_version }));
    console.log(JSON.stringify({ event: "host.connected", host_id: h.host_id }));

    return new Response(null, { status: 101, webSocket: client });
  }

  /**
   * The newest open socket, or undefined.
   *
   * Trap: getWebSockets() still returns a replaced or half-closed socket
   * until the runtime observes its close. Order is not defined. So the
   * choice is by readyState and by the attached connect time.
   */
  private liveSocket(): WebSocket | undefined {
    let best: WebSocket | undefined;
    let bestAt = -1;
    for (const ws of this.ctx.getWebSockets()) {
      if (ws.readyState !== WS_OPEN) continue;
      const at = socketMeta(ws)?.connected_at_ms ?? 0;
      if (at > bestAt) {
        best = ws;
        bestAt = at;
      }
    }
    return best;
  }

  override async webSocketMessage(_ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== "string") return;
    if (message.length > MAX_FRAME_CHARS) return;

    let frame: HostFrame;
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
        if (!this.pending.has(frame.id)) {
          // Late answers still matter for the audit trail. The host has spent the grant.
          this.sql.exec(
            "UPDATE redemptions SET status = 'late' WHERE request_id = ? AND status = 'timeout'",
            frame.id,
          );
          return;
        }
        const { response, audit } = hostResponse(frame);
        this.settle(frame.id, audit, response);
        return;
      }
      default:
        // The frame vocabulary is fixed by the protocol. Unknown frames are dropped.
        return;
    }
  }

  override async webSocketClose(ws: WebSocket, code: number): Promise<void> {
    const meta = socketMeta(ws);
    console.log(JSON.stringify({ event: "host.disconnected", host_id: meta?.host_id, code }));
    if (!meta) return;
    // Requests sent on this socket will never get an answer. Fail them now.
    for (const [requestId, p] of this.pending) {
      if (p.socketId !== meta.connected_at_ms) continue;
      this.settle(requestId, "dropped", errorResponse(ERR.HOST_OFFLINE, "the host connection dropped"));
    }
  }

  override async webSocketError(): Promise<void> {
    /* the runtime closes the socket */
  }

  // --------------------------------------------------------------- grants

  private async publishGrant(request: Request, grantId: string): Promise<Response> {
    const h = this.hostRow();
    if (!h) return errorResponse(ERR.HOST_NOT_FOUND, "no such host");

    const body = (await request.json()) as Record<string, unknown>;
    const grant = parseGrant(body.grant);
    const signature = parseSignature(body);

    if (grant.grant_id !== grantId) {
      return errorResponse(ERR.BAD_REQUEST, "grant_id in body does not match the URL");
    }
    if (grant.host_id !== h.host_id) {
      return errorResponse(ERR.ID_MISMATCH, "grant is addressed to a different host");
    }
    // Only the host can publish a grant for itself.
    const identity = b64uDecode(h.identity_public_key);
    if (!(await verifyEd25519(identity, canonicalGrant(grant), signature))) {
      return errorResponse(ERR.BAD_SIGNATURE, "grant signature does not verify");
    }

    const now = this.now();
    if (Number(grant.expires_at) <= now) {
      return errorResponse(ERR.GRANT_EXPIRED, "grant is already expired");
    }
    // A far-future created_at will hold an active slot past retention.
    if (Number(grant.created_at) > now + SKEW_REGISTRATION) {
      return errorResponse(ERR.BAD_REQUEST, "grant created_at is in the future");
    }

    const active = this.sql
      .exec("SELECT COUNT(*) AS n FROM grants WHERE expires_at > ?", now)
      .one() as { n: number };
    const alreadyKnown = this.grantRow(grantId) !== undefined;
    if (active.n >= MAX_PUBLISHED_GRANTS && !alreadyKnown) {
      return errorResponse(ERR.TOO_MANY_GRANTS, "too many active grants for this host");
    }

    this.sql.exec(
      `INSERT INTO grants (grant_id, signed_payload, host_signature, ssh_user, created_at, expires_at, published_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(grant_id) DO UPDATE SET
         signed_payload = excluded.signed_payload,
         host_signature = excluded.host_signature,
         ssh_user       = excluded.ssh_user,
         created_at     = excluded.created_at,
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

  private grantRow(grantId: string): GrantRow | undefined {
    return this.sql.exec<GrantRow>("SELECT * FROM grants WHERE grant_id = ?", grantId).toArray()[0];
  }

  private grantRecord(grantId: string): Response {
    const h = this.hostRow();
    if (!h) return errorResponse(ERR.HOST_NOT_FOUND, "no such host");
    const row = this.grantRow(grantId);
    if (!row) return errorResponse(ERR.GRANT_NOT_FOUND, "no such grant");
    return jsonResponse({
      grant: JSON.parse(row.signed_payload),
      signature: row.host_signature,
      host: { hostname: h.hostname, ssh_port: h.ssh_port, ssh_user: h.ssh_user },
      connected: this.liveSocket() !== undefined,
    });
  }

  // ------------------------------------------------------------- redemption

  /**
   * Checks the envelope, then forwards it to the host. The checks run in
   * cost order: everything rejected before the socket send costs the
   * customer's machine nothing.
   */
  private async redeem(request: Request, grantId: string): Promise<Response> {
    const h = this.hostRow();
    if (!h) return errorResponse(ERR.HOST_NOT_FOUND, "no such host");

    const raw = await request.text();
    const body = parseJsonObject(raw);
    if (!body) return errorResponse(ERR.BAD_REQUEST, "body must be a JSON object");
    const { payload, agent_signature: agentSignature } = parseRedemptionRequest(body);

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

    // The ID must be the hash of the key in the payload. Without this check
    // a stranger can sign with any key and borrow a registered agent_id.
    if ((await deriveAgentId(payload.agent_public_key)) !== payload.agent_id) {
      return errorResponse(ERR.ID_MISMATCH, "agent_id does not match agent_public_key");
    }
    // Attribution only. The host verifies this again and its opinion is the one that counts.
    if (!(await verifyEd25519(payload.agent_public_key, canonicalRedemptionSig(payload), agentSignature))) {
      return errorResponse(ERR.BAD_SIGNATURE, "agent signature does not verify");
    }

    const row = this.grantRow(grantId);
    if (!row) return errorResponse(ERR.GRANT_NOT_FOUND, "no such grant");
    if (row.expires_at <= now) {
      // Advisory. The host makes the authoritative expiry decision.
      return errorResponse(ERR.GRANT_EXPIRED, "grant has expired");
    }

    // Registration is an abuse control, not a security boundary. It makes
    // reaching a customer's machine cost a proof of work.
    const registered = await this.registeredAgentKey(payload.agent_id);
    if (!registered) {
      return errorResponse(ERR.AGENT_NOT_FOUND, "register an agent identity before redeeming");
    }
    if (registered !== b64uEncode(payload.agent_public_key)) {
      return errorResponse(ERR.ID_MISMATCH, "agent_public_key does not match the registered key");
    }

    const socket = this.liveSocket();
    if (!socket) return errorResponse(ERR.HOST_OFFLINE, "the host is not currently connected");
    const keyFp = await sshKeyFingerprint(payload.ssh_public_key);

    // Counted immediately before the machine is woken. That is the protected resource.
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
      keyFp,
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
    return await this.forwardToHost(socket, requestId, raw);
  }

  /** The registered public key for an agent id, or undefined when unregistered. */
  private async registeredAgentKey(agentId: string): Promise<string | undefined> {
    const res = await this.env.AGENTS.get(this.env.AGENTS.idFromName(agentId)).fetch(
      new Request(`https://do/agent/${agentId}`, { method: "GET" }),
    );
    if (!res.ok) return undefined;
    const rec = (await res.json()) as AgentRecord;
    return typeof rec.public_key === "string" ? rec.public_key : undefined;
  }

  /**
   * Sends the envelope as opaque base64 and waits for the answer. The host
   * must verify the bytes the agent signed, not bytes this service produced.
   */
  private forwardToHost(socket: WebSocket, requestId: string, raw: string): Promise<Response> {
    const frame = JSON.stringify({
      t: "redeem.request",
      id: requestId,
      body_b64: b64uEncode(new TextEncoder().encode(raw)),
    });
    const socketId = socketMeta(socket)?.connected_at_ms ?? 0;
    return new Promise<Response>((resolve) => {
      const timer = setTimeout(() => {
        this.settle(requestId, "timeout", errorResponse(ERR.HOST_TIMEOUT, "the host did not answer in time"));
      }, REDEEM_TIMEOUT_MS);
      this.pending.set(requestId, { resolve, timer, socketId });
      try {
        socket.send(frame);
      } catch {
        this.settle(requestId, "dropped", errorResponse(ERR.HOST_OFFLINE, "the host connection dropped"));
      }
    });
  }

  /** Finishes one in-flight redemption: records the outcome and answers the waiting request. */
  private settle(requestId: string, status: string, response: Response): void {
    const waiter = this.pending.get(requestId);
    if (!waiter) return;
    this.pending.delete(requestId);
    clearTimeout(waiter.timer);
    this.sql.exec(
      "UPDATE redemptions SET completed_at = ?, status = ? WHERE request_id = ?",
      this.now(),
      status,
      requestId,
    );
    waiter.resolve(response);
  }

  // -------------------------------------------------------------- housekeeping

  /**
   * Points this host's managed name at `ip`. Returns the name on success,
   * and null whenever naming is off, not asked for, or simply failed.
   *
   * Two separate gates decide whether a record is written, and both matter:
   *
   *   - the name is derived from the host id, never read from the
   *     registration, so a host can only affect its own label; and
   *   - the record is written only when the host's *signed* hostname is
   *     already that derived name, which is how a host asks for one. A host
   *     enrolled with its own address is left alone.
   *
   * Nothing here can fail a registration or a reconnect. A host without a
   * name is still registered, still connected, and still reachable at the
   * address it was enrolled with.
   */
  private async syncDns(
    hostId: string,
    signedHostname: string,
    ip: string | null,
  ): Promise<string | null> {
    const cfg = dnsConfig(this.env);
    if (!cfg || !ip) return null;

    const name = hostRecordName(hostId, cfg.suffix);
    if (!name || signedHostname.trim().toLowerCase() !== name) return null;

    try {
      const result = await syncHostRecord(cfg, name, ip);
      if (!result.ok) {
        console.error(
          JSON.stringify({ event: "host.dns_failed", host_id: hostId, reason: result.reason }),
        );
        return null;
      }
      this.sql.exec("UPDATE host SET dns_name = ?, dns_ip = ? WHERE guard = 1", name, ip);
      console.log(
        JSON.stringify({ event: "host.dns_synced", host_id: hostId, name, type: result.type }),
      );
      return name;
    } catch (e) {
      // A timeout or a network fault reaching the Cloudflare API lands here.
      console.error(
        JSON.stringify({ event: "host.dns_failed", host_id: hostId, message: String(e) }),
      );
      return null;
    }
  }

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

  /** Records one forwarded attempt. Returns false, and records nothing, when the window is full. */
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
    if (!this.hasSchema()) return;
    const now = this.now();
    this.sql.exec("DELETE FROM grants WHERE expires_at < ?", now - GRANT_RETENTION_S);
    this.sql.exec("DELETE FROM redemptions WHERE requested_at < ?", now - REDEMPTION_RETENTION_S);
    this.sql.exec("DELETE FROM nonces WHERE seen_at < ?", now - SKEW_REGISTRATION * 4);
    this.sql.exec("DELETE FROM redeem_attempts WHERE at < ?", now - REDEEM_ATTEMPT_WINDOW_S);
    await this.ctx.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
  }
}

function socketMeta(ws: WebSocket): SocketMeta | undefined {
  try {
    return (ws.deserializeAttachment() as SocketMeta | null) ?? undefined;
  } catch {
    return undefined;
  }
}

/** HTTP statuses that must not carry a body. */
const NO_BODY_STATUSES = new Set([204, 205, 304]);

/**
 * Turns a redeem.response frame into the HTTP answer for the redeemer.
 *
 * The body is relayed as opaque bytes. A parse here lets this service
 * reshape the host's verdict, and a JSON round trip corrupts any 64-bit
 * value in it. A malformed frame becomes an INTERNAL error, never an
 * exception. The waiter must always be answered.
 */
function hostResponse(frame: HostFrame): { response: Response; audit: string } {
  const malformed = {
    response: errorResponse(ERR.INTERNAL, "malformed response from host"),
    audit: "malformed",
  };
  const status = frame.status;
  if (
    typeof status !== "number" ||
    !Number.isInteger(status) ||
    status < 200 ||
    status > 599 ||
    NO_BODY_STATUSES.has(status)
  ) {
    return malformed;
  }
  let body: Uint8Array;
  try {
    body = b64uDecode(typeof frame.body_b64 === "string" ? frame.body_b64 : "");
  } catch {
    return malformed;
  }
  try {
    return {
      response: new Response(body, {
        status,
        headers: { "content-type": "application/json; charset=utf-8" },
      }),
      audit: status === 200 ? "issued" : "rejected",
    };
  } catch {
    return malformed;
  }
}
