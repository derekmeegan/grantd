/**
 * AgentDO, one Durable Object per registered agent identity.
 *
 * It stores a public key. Registration is a name for attribution and a
 * handle for rate limiting. It grants nothing.
 */

import { DurableObject } from "cloudflare:workers";
import { ERR, errorResponse, jsonResponse } from "../errors";
import { b64uEncode } from "../crypto/encoding";
import { agentId as deriveAgentId, verifyEd25519 } from "../crypto/ids";
import {
  canonicalAgentRegistration,
  parseAgentRegistration,
  parseSignature,
  ParseError,
  SKEW_REGISTRATION,
  withinSkew,
} from "../protocol";
import type { Env } from "../env";

export interface AgentRecord {
  agent_id: string;
  public_key: string;
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
    const signature = parseSignature(body);

    // The ID is a hash of the key. Recompute it instead of trusting it.
    const derived = await deriveAgentId(reg.public_key);
    if (derived !== reg.agent_id) {
      return errorResponse(ERR.ID_MISMATCH, "agent_id does not match public_key");
    }

    const now = Math.floor(Date.now() / 1000);
    if (!withinSkew(now, reg.timestamp, SKEW_REGISTRATION)) {
      return errorResponse(ERR.STALE_TIMESTAMP, "registration timestamp is outside the allowed window");
    }
    // The signature is the proof that the registrant holds the private key.
    if (!(await verifyEd25519(reg.public_key, canonicalAgentRegistration(reg), signature))) {
      return errorResponse(ERR.BAD_SIGNATURE, "registration signature does not verify");
    }

    const existing = await this.ctx.storage.get<AgentRecord>("record");
    const encoded = b64uEncode(reg.public_key);
    if (existing) {
      if (existing.public_key !== encoded) {
        return errorResponse(ERR.ID_MISMATCH, "public key for this agent_id is immutable");
      }
      existing.last_seen_at = now;
      await this.ctx.storage.put("record", existing);
      return jsonResponse({ agent_id: reg.agent_id, registered: true, existing: true });
    }

    const rec: AgentRecord = {
      agent_id: reg.agent_id,
      public_key: encoded,
      created_at: now,
      last_seen_at: now,
    };
    await this.ctx.storage.put("record", rec);
    console.log(JSON.stringify({ event: "agent.registered", agent_id: reg.agent_id }));
    return jsonResponse({ agent_id: reg.agent_id, registered: true, existing: false }, 201);
  }

  private async publicRecord(): Promise<Response> {
    const rec = await this.ctx.storage.get<AgentRecord>("record");
    if (!rec) return errorResponse(ERR.AGENT_NOT_FOUND, "no such agent");
    const out: AgentRecord = {
      agent_id: rec.agent_id,
      public_key: rec.public_key,
      created_at: rec.created_at,
      last_seen_at: rec.last_seen_at,
    };
    return jsonResponse(out);
  }
}
