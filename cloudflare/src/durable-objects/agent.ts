/**
 * AgentDO — one Durable Object per registered agent identity.
 *
 * It stores a public key and nothing else of consequence. Being registered is
 * not a permission: it is a name to attribute redemptions to and a handle to
 * rate limit. A visiting agent with a valid registration and no grant secret
 * can do exactly nothing.
 */

import { DurableObject } from "cloudflare:workers";
import { ERR, errorResponse, jsonResponse } from "../errors";
import { b64uEncode } from "../crypto/encoding";
import { agentId as deriveAgentId, verifyEd25519 } from "../crypto/ids";
import {
  canonicalAgentRegistration,
  parseAgentRegistration,
  ParseError,
  SKEW_REGISTRATION,
  withinSkew,
} from "../protocol";
import type { Env } from "../env";

interface Record_ {
  agent_id: string;
  public_key: string;
  captcha_version: number;
  created_at: number;
  last_seen_at: number;
}

export class AgentDO extends DurableObject<Env> {
  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const rest = url.pathname.split("/").filter(Boolean).slice(2);
    try {
      if (request.method === "PUT" && rest.length === 0) return await this.register(request);
      if (request.method === "GET" && rest.length === 0) return await this.publicRecord();
      if (request.method === "POST" && rest[0] === "seen") return await this.touch();
      return errorResponse(ERR.BAD_REQUEST, "no such agent route", 404);
    } catch (e) {
      if (e instanceof ParseError) return errorResponse(e.code, e.message);
      console.error("agentdo error", { message: String(e) });
      return errorResponse(ERR.INTERNAL, "internal error");
    }
  }

  private async register(request: Request): Promise<Response> {
    const body = (await request.json()) as Record<string, unknown>;
    const reg = parseAgentRegistration(body.registration);
    const signature = decodeSig(body.signature);

    // Self-certifying: the ID must be the hash of the key being registered.
    const derived = await deriveAgentId(reg.public_key);
    if (derived !== reg.agent_id) {
      return errorResponse(ERR.ID_MISMATCH, "agent_id does not match public_key");
    }

    const now = Math.floor(Date.now() / 1000);
    if (!withinSkew(now, reg.timestamp, SKEW_REGISTRATION)) {
      return errorResponse(ERR.STALE_TIMESTAMP, "registration timestamp is outside the allowed window");
    }
    // Proof of possession: the signature is the only thing that shows the
    // registrant actually holds the private half.
    if (!(await verifyEd25519(reg.public_key, canonicalAgentRegistration(reg), signature))) {
      return errorResponse(ERR.BAD_SIGNATURE, "registration signature does not verify");
    }

    const existing = await this.ctx.storage.get<Record_>("record");
    const encoded = b64uEncode(reg.public_key);
    if (existing) {
      if (existing.public_key !== encoded) {
        return errorResponse(ERR.ID_MISMATCH, "public key for this agent_id is immutable");
      }
      existing.last_seen_at = now;
      await this.ctx.storage.put("record", existing);
      return jsonResponse({ agent_id: reg.agent_id, registered: true, existing: true });
    }

    const rec: Record_ = {
      agent_id: reg.agent_id,
      public_key: encoded,
      captcha_version: 1,
      created_at: now,
      last_seen_at: now,
    };
    await this.ctx.storage.put("record", rec);
    console.log(JSON.stringify({ event: "agent.registered", agent_id: reg.agent_id }));
    return jsonResponse({ agent_id: reg.agent_id, registered: true, existing: false }, 201);
  }

  private async publicRecord(): Promise<Response> {
    const rec = await this.ctx.storage.get<Record_>("record");
    if (!rec) return errorResponse(ERR.AGENT_NOT_FOUND, "no such agent");
    return jsonResponse(rec);
  }

  private async touch(): Promise<Response> {
    const rec = await this.ctx.storage.get<Record_>("record");
    if (!rec) return errorResponse(ERR.AGENT_NOT_FOUND, "no such agent");
    rec.last_seen_at = Math.floor(Date.now() / 1000);
    await this.ctx.storage.put("record", rec);
    return jsonResponse({ agent_id: rec.agent_id, seen: true });
  }
}

function decodeSig(v: unknown): Uint8Array {
  if (typeof v !== "string") throw new ParseError(ERR.BAD_REQUEST, "signature must be a base64url string");
  const padded = v.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (v.length % 4)) % 4);
  let bin: string;
  try {
    bin = atob(padded);
  } catch {
    throw new ParseError(ERR.BAD_REQUEST, "signature must be base64url without padding");
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (out.length !== 64) throw new ParseError(ERR.BAD_REQUEST, "signature must be 64 bytes");
  return out;
}
