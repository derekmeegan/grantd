/**
 * ChallengeDO, one Durable Object per registration challenge.
 *
 * Its job is atomic consumption. A challenge is usable exactly once, even
 * when two submissions arrive at the same instant.
 */

import { DurableObject } from "cloudflare:workers";
import { ERR, errorResponse, jsonResponse } from "../errors";
import { b64uDecode, b64uEncode } from "../crypto/encoding";
import { verifyPow } from "../captcha";
import type { Env } from "../env";

/** A stale challenge is a replay opportunity, so the lifetime is short. */
const TTL_SECONDS = 600;

/** About 1M hashes: one second for one agent, real money for a million. */
const DEFAULT_DIFFICULTY_BITS = 20;

/** Lowest difficulty accepted outside tests. Below this the proof of work is free. */
const MIN_PRODUCTION_DIFFICULTY_BITS = 16;

interface State {
  challenge_id: string;
  pow_prefix: string;
  difficulty_bits: number;
  created_at: number;
  expires_at: number;
  consumed_at: number | null;
}

export class ChallengeDO extends DurableObject<Env> {
  /**
   * Reads POW_DIFFICULTY_BITS. A value below the production floor is used
   * only when POW_ALLOW_LOW_DIFFICULTY is "1". Any other bad value falls
   * back to the default.
   */
  private difficultyBits(): number {
    const raw = this.env.POW_DIFFICULTY_BITS;
    if (!raw) return DEFAULT_DIFFICULTY_BITS;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 0 || n > 32) return DEFAULT_DIFFICULTY_BITS;
    const lowAllowed = this.env.POW_ALLOW_LOW_DIFFICULTY === "1";
    if (n < MIN_PRODUCTION_DIFFICULTY_BITS && !lowAllowed) return DEFAULT_DIFFICULTY_BITS;
    return n;
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const rest = url.pathname.split("/").filter(Boolean).slice(2);

    if (request.method === "POST" && rest.length === 0) {
      return await this.create(url.searchParams.get("id") ?? "");
    }
    if (request.method === "POST" && rest[0] === "consume") {
      return await this.consume(request);
    }
    return errorResponse(ERR.BAD_REQUEST, "no such challenge route", 404);
  }

  private async create(challengeId: string): Promise<Response> {
    const prefix = new Uint8Array(16);
    crypto.getRandomValues(prefix);
    const now = Math.floor(Date.now() / 1000);

    const state: State = {
      challenge_id: challengeId,
      pow_prefix: b64uEncode(prefix),
      difficulty_bits: this.difficultyBits(),
      created_at: now,
      expires_at: now + TTL_SECONDS,
      consumed_at: null,
    };
    await this.ctx.storage.put("state", state);
    // The object is useless after expiry. The alarm deletes it.
    await this.ctx.storage.setAlarm(Date.now() + (TTL_SECONDS + 60) * 1000);

    console.log(JSON.stringify({ event: "agent.challenge_created", challenge_id: challengeId }));

    return jsonResponse(
      {
        challenge_id: challengeId,
        version: 1,
        expires_at: state.expires_at,
        pow: { prefix: state.pow_prefix, difficulty_bits: state.difficulty_bits },
      },
      201,
    );
  }

  /** Consumes the challenge. The read-check-write runs as one unit. */
  private async consume(request: Request): Promise<Response> {
    const body = (await request.json()) as { pow_nonce?: unknown };
    const powNonce = typeof body.pow_nonce === "string" ? body.pow_nonce : "";

    return await this.ctx.blockConcurrencyWhile(async () => {
      const state = await this.ctx.storage.get<State>("state");
      if (!state) return errorResponse(ERR.CHALLENGE_NOT_FOUND, "no such challenge");

      const now = Math.floor(Date.now() / 1000);
      if (state.expires_at <= now) {
        return errorResponse(ERR.CHALLENGE_NOT_FOUND, "challenge has expired");
      }
      if (state.consumed_at !== null) {
        return errorResponse(ERR.CHALLENGE_CONSUMED, "challenge has already been used");
      }

      const prefix = b64uDecode(state.pow_prefix);
      if (!(await verifyPow(prefix, state.difficulty_bits, powNonce))) {
        return errorResponse(ERR.BAD_ANSWER, "proof of work is invalid");
      }

      state.consumed_at = now;
      await this.ctx.storage.put("state", state);
      return jsonResponse({ challenge_id: state.challenge_id, consumed: true });
    });
  }

  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
