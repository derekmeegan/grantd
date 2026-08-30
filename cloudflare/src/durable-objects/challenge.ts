/**
 * ChallengeDO — one Durable Object per Agent Captcha challenge.
 *
 * Its only real job is to make consumption atomic: a challenge must be usable
 * exactly once, even if the same answer is submitted from two places at the
 * same instant. A Durable Object gives that for free, which is why this is an
 * object rather than a row somewhere.
 */

import { DurableObject } from "cloudflare:workers";
import { ERR, errorResponse, jsonResponse } from "../errors";
import { b64uEncode } from "../crypto/encoding";
import { answerMatches, generateChallenge, verifyPow } from "../captcha";
import type { Env } from "../env";

/** Challenges are short-lived; a stale one is a replay opportunity, not a convenience. */
const TTL_SECONDS = 600;

/** ~1M hashes: a second for one agent, real money for a million registrations. */
const DIFFICULTY_BITS = 20;

interface State {
  challenge_id: string;
  question: string;
  answer: string;
  pow_prefix: string;
  difficulty_bits: number;
  created_at: number;
  expires_at: number;
  consumed_at: number | null;
}

export class ChallengeDO extends DurableObject<Env> {
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
    const spec = generateChallenge();
    const prefix = new Uint8Array(16);
    crypto.getRandomValues(prefix);
    const now = Math.floor(Date.now() / 1000);

    const state: State = {
      challenge_id: challengeId,
      question: spec.question,
      answer: spec.answer,
      pow_prefix: b64uEncode(prefix),
      difficulty_bits: DIFFICULTY_BITS,
      created_at: now,
      expires_at: now + TTL_SECONDS,
      consumed_at: null,
    };
    await this.ctx.storage.put("state", state);
    // The object is useless after expiry; let it clean itself up rather than
    // accumulating one abandoned object per abandoned registration attempt.
    await this.ctx.storage.setAlarm(Date.now() + (TTL_SECONDS + 60) * 1000);

    console.log(JSON.stringify({ event: "agent.challenge_created", challenge_id: challengeId }));

    // The expected answer is deliberately not in this response.
    return jsonResponse(
      {
        challenge_id: challengeId,
        version: 1,
        expires_at: state.expires_at,
        pow: { prefix: state.pow_prefix, difficulty_bits: state.difficulty_bits },
        question: state.question,
      },
      201,
    );
  }

  /**
   * Consumes the challenge. The whole read-check-write runs inside
   * blockConcurrencyWhile so that two simultaneous submissions cannot both see
   * an unconsumed challenge.
   */
  private async consume(request: Request): Promise<Response> {
    const body = (await request.json()) as { answer?: unknown; pow_nonce?: unknown };
    const answer = typeof body.answer === "string" ? body.answer : "";
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

      const prefix = decodePrefix(state.pow_prefix);
      if (!(await verifyPow(prefix, state.difficulty_bits, powNonce))) {
        return errorResponse(ERR.BAD_ANSWER, "proof of work is invalid");
      }
      if (!answerMatches(state.answer, answer)) {
        return errorResponse(ERR.BAD_ANSWER, "challenge answer is incorrect");
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

function decodePrefix(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
