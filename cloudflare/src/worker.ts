/**
 * grantd coordination Worker.
 *
 * A router. It parses HTTP, enforces sizes and rate limits, checks that
 * identifiers are well formed, and hands the request to the Durable Object that
 * owns that host, agent, or challenge. It deliberately holds no authoritative
 * state and makes no authorization decision about SSH access — it could not
 * make one correctly even if it tried, because the only thing that authorizes
 * access is a secret it never receives.
 */

import { ERR, errorResponse, jsonResponse, textResponse } from "./errors";
import { AGENT_ID_RE, GRANT_ID_RE, HOST_ID_RE, newChallengeId } from "./crypto/ids";
import { MAX_REQUEST_BYTES } from "./protocol";
import { docsMarkdown, grantInstructions, installScript } from "./routes/docs";
import type { Env, RateLimiter } from "./env";

export { HostDO } from "./durable-objects/host";
export { AgentDO } from "./durable-objects/agent";
export { ChallengeDO } from "./durable-objects/challenge";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      return await route(request, env, ctx);
    } catch (e) {
      console.error("worker error", { message: String(e) });
      return errorResponse(ERR.INTERNAL, "internal error");
    }
  },
} satisfies ExportedHandler<Env>;

async function route(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const origin = env.PUBLIC_ORIGIN || url.origin;
  const seg = url.pathname.split("/").filter(Boolean);

  if (request.method === "GET" && seg.length === 0) {
    return textResponse(docsMarkdown(origin), 200, "text/markdown; charset=utf-8");
  }
  if (request.method === "GET" && seg[0] === "health") {
    return jsonResponse({ ok: true, protocol_version: 1 });
  }
  if (request.method === "GET" && seg[0] === "install") {
    return textResponse(installScript(origin), 200, "text/x-shellscript; charset=utf-8");
  }

  // Human- and agent-readable capability landing page. The secret is in the
  // fragment, so it never reaches this handler; nothing here reads, logs, or
  // accepts one, and a request that puts a secret in the path or query is
  // answered without echoing it back.
  if (request.method === "GET" && seg[0] === "g" && seg.length === 3) {
    const [, hostId, grantId] = seg;
    if (!HOST_ID_RE.test(hostId) || !GRANT_ID_RE.test(grantId)) {
      return errorResponse(ERR.BAD_REQUEST, "malformed capability url");
    }
    return textResponse(grantInstructions(origin, hostId, grantId));
  }

  // Release artifacts, served from R2 so the installer needs no second origin.
  // Read-only: there is no upload path here, and the release signing key lives
  // nowhere near Cloudflare.
  if (request.method === "GET" && seg[0] === "releases") {
    return await serveRelease(env, seg.slice(1).join("/"));
  }

  if (seg[0] === "v1") return await v1(request, env, seg.slice(1));

  return errorResponse(ERR.BAD_REQUEST, "no such route", 404);
}

async function v1(request: Request, env: Env, seg: string[]): Promise<Response> {
  // ---- agent challenges -------------------------------------------------
  if (request.method === "POST" && seg[0] === "agent-challenges" && seg.length === 1) {
    if (!(await allow(env.CHALLENGE_LIMITER, clientKey(request), "challenge"))) {
      return errorResponse(ERR.RATE_LIMITED, "too many challenge requests");
    }
    const id = newChallengeId();
    const stub = env.CHALLENGES.get(env.CHALLENGES.idFromName(id));
    return await stub.fetch(
      new Request(`https://do/challenge/${id}?id=${id}`, { method: "POST" }),
    );
  }

  // ---- agents -----------------------------------------------------------
  if (request.method === "POST" && seg[0] === "agents" && seg.length === 1) {
    if (!(await allow(env.REGISTRATION_LIMITER, clientKey(request), "registration"))) {
      return errorResponse(ERR.RATE_LIMITED, "too many registration attempts");
    }
    const body = await readJson(request);
    if (body instanceof Response) return body;

    const reg = (body as Record<string, unknown>).registration as Record<string, unknown> | undefined;
    const challengeId = typeof reg?.challenge_id === "string" ? reg.challenge_id : "";
    const agentId = typeof reg?.agent_id === "string" ? reg.agent_id : "";
    const powNonce = typeof reg?.pow_nonce === "string" ? reg.pow_nonce : "";
    if (!AGENT_ID_RE.test(agentId)) {
      return errorResponse(ERR.BAD_REQUEST, "malformed agent_id");
    }
    if (!challengeId) {
      return errorResponse(ERR.BAD_REQUEST, "challenge_id is required");
    }

    // Consume the challenge first. If registration then fails for any reason
    // the challenge is still spent, which is the safe direction: a failed
    // attempt costs the caller a fresh proof of work.
    const chStub = env.CHALLENGES.get(env.CHALLENGES.idFromName(challengeId));
    const consumed = await chStub.fetch(
      new Request(`https://do/challenge/${challengeId}/consume`, {
        method: "POST",
        body: JSON.stringify({ pow_nonce: powNonce }),
        headers: { "content-type": "application/json" },
      }),
    );
    if (!consumed.ok) return consumed;

    const stub = env.AGENTS.get(env.AGENTS.idFromName(agentId));
    return await stub.fetch(
      new Request(`https://do/agent/${agentId}`, {
        method: "PUT",
        body: JSON.stringify(body),
        headers: { "content-type": "application/json" },
      }),
    );
  }

  if (request.method === "GET" && seg[0] === "agents" && seg.length === 2) {
    if (!AGENT_ID_RE.test(seg[1])) return errorResponse(ERR.BAD_REQUEST, "malformed agent_id");
    const stub = env.AGENTS.get(env.AGENTS.idFromName(seg[1]));
    return await stub.fetch(new Request(`https://do/agent/${seg[1]}`, { method: "GET" }));
  }

  // ---- hosts ------------------------------------------------------------
  if (seg[0] === "hosts" && seg.length >= 2) {
    const hostId = seg[1];
    if (!HOST_ID_RE.test(hostId)) return errorResponse(ERR.BAD_REQUEST, "malformed host_id");
    const stub = env.HOSTS.get(env.HOSTS.idFromName(hostId));
    const rest = seg.slice(2);

    if (rest.length === 0 && (request.method === "PUT" || request.method === "GET")) {
      const init: RequestInit = { method: request.method };
      if (request.method === "PUT") {
        const body = await readJson(request);
        if (body instanceof Response) return body;
        init.body = JSON.stringify(body);
        init.headers = { "content-type": "application/json" };
      }
      return await stub.fetch(new Request(`https://do/host/${hostId}`, init));
    }

    // Rendezvous upgrade. Headers carry the host's signature; the body is empty.
    if (rest.length === 1 && rest[0] === "connect" && request.method === "GET") {
      return await stub.fetch(
        new Request(`https://do/host/${hostId}/connect`, {
          method: "GET",
          headers: request.headers,
        }),
      );
    }

    if (rest[0] === "grants" && rest.length === 2) {
      const grantId = rest[1];
      if (!GRANT_ID_RE.test(grantId)) return errorResponse(ERR.BAD_REQUEST, "malformed grant_id");
      if (request.method === "GET") {
        return await stub.fetch(
          new Request(`https://do/host/${hostId}/grants/${grantId}`, { method: "GET" }),
        );
      }
      if (request.method === "PUT" || request.method === "DELETE") {
        const body = await readJson(request);
        if (body instanceof Response) return body;
        return await stub.fetch(
          new Request(`https://do/host/${hostId}/grants/${grantId}`, {
            method: request.method,
            body: JSON.stringify(body),
            headers: { "content-type": "application/json" },
          }),
        );
      }
    }

    if (rest[0] === "grants" && rest.length === 3 && rest[2] === "redeem" && request.method === "POST") {
      const grantId = rest[1];
      if (!GRANT_ID_RE.test(grantId)) return errorResponse(ERR.BAD_REQUEST, "malformed grant_id");
      // Two limiters, because they stop different attacks. The IP-keyed one
      // stops one noisy source; the grant-keyed one stops a distributed flood
      // against a single capability, which is the case that would otherwise
      // let anyone with a grant id repeatedly wake someone else's machine.
      if (!(await allow(env.REDEMPTION_LIMITER, clientKey(request), "redemption-ip"))) {
        return errorResponse(ERR.RATE_LIMITED, "too many redemption attempts");
      }
      if (
        !(await allow(env.REDEMPTION_GRANT_LIMITER, `${hostId}:${grantId}`, "redemption-grant"))
      ) {
        return errorResponse(ERR.RATE_LIMITED, "too many redemption attempts for this grant");
      }
      const raw = await readRaw(request);
      if (raw instanceof Response) return raw;
      // Forwarded verbatim: the host must verify the bytes the agent signed,
      // not a re-serialization produced here.
      return await stub.fetch(
        new Request(`https://do/host/${hostId}/grants/${grantId}/redeem`, {
          method: "POST",
          body: raw,
          headers: { "content-type": "application/json" },
        }),
      );
    }
  }

  return errorResponse(ERR.BAD_REQUEST, "no such route", 404);
}

async function serveRelease(env: Env, key: string): Promise<Response> {
  if (!env.RELEASES) return errorResponse(ERR.BAD_REQUEST, "release distribution is not configured", 404);
  if (!/^[A-Za-z0-9._\/-]{1,200}$/.test(key) || key.includes("..")) {
    return errorResponse(ERR.BAD_REQUEST, "malformed release path");
  }
  const object = await env.RELEASES.get(key);
  if (!object) return errorResponse(ERR.BAD_REQUEST, "no such release artifact", 404);
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("cache-control", "public, max-age=300");
  if (!headers.has("content-type")) headers.set("content-type", "application/octet-stream");
  return new Response(object.body, { headers });
}

// ---------------------------------------------------------------- utilities

async function readRaw(request: Request): Promise<string | Response> {
  const declared = request.headers.get("content-length");
  if (declared && Number(declared) > MAX_REQUEST_BYTES) {
    return errorResponse(ERR.BAD_REQUEST, "request body too large", 413);
  }
  const text = await request.text();
  if (text.length > MAX_REQUEST_BYTES) {
    return errorResponse(ERR.BAD_REQUEST, "request body too large", 413);
  }
  return text;
}

async function readJson(request: Request): Promise<unknown | Response> {
  const raw = await readRaw(request);
  if (raw instanceof Response) return raw;
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return errorResponse(ERR.BAD_REQUEST, "body must be a JSON object");
    }
    return parsed;
  } catch {
    return errorResponse(ERR.BAD_REQUEST, "malformed JSON body");
  }
}

/**
 * Rate limit key for the caller's IP, or null when there is no client IP.
 *
 * Returning null rather than a constant matters. A shared fallback bucket would
 * mean that in any context without CF-Connecting-IP — local dev, tests, a
 * misconfigured route — every caller in the world shares one limit and throttles
 * everyone else. Cloudflare sets this header itself and overwrites any
 * client-supplied value, so its absence means "not behind Cloudflare", not
 * "attacker removed it".
 */
function clientKey(request: Request): string | null {
  return request.headers.get("CF-Connecting-IP");
}

/**
 * Applies a rate limiter if the binding exists.
 *
 * Fails open, because a broken limiter should not take the service down — but
 * it logs when it does, so that a persistently failing binding is visible
 * instead of silently disabling the limit forever.
 */
async function allow(
  limiter: RateLimiter | undefined,
  key: string | null,
  scope: string,
): Promise<boolean> {
  if (!limiter || key === null) return true;
  try {
    const { success } = await limiter.limit({ key });
    return success;
  } catch (e) {
    console.error(
      JSON.stringify({ event: "ratelimit.unavailable", scope, message: String(e) }),
    );
    return true;
  }
}
