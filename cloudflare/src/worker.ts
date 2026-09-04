/**
 * grantd coordination Worker.
 *
 * A router. It parses HTTP, enforces sizes and rate limits, checks that
 * identifiers are well formed, and hands the request to the Durable Object
 * that owns the host, agent, or challenge. It makes no authorization decision
 * about SSH access. The only thing that authorizes access is a secret it
 * never receives.
 */

import { ERR, errorResponse, jsonResponse, scriptResponse, textResponse } from "./errors";
import { AGENT_ID_RE, CHALLENGE_ID_RE, GRANT_ID_RE, HOST_ID_RE, newChallengeId } from "./crypto/ids";
import { MAX_REQUEST_BYTES, parseJsonObject } from "./protocol";
import { CLIENT_IP_HEADER } from "./dns";
import { docsMarkdown, grantInstructions } from "./routes/docs";
// Imported as text so the script agents download is the one the test suite runs.
import redeemScript from "../../install/redeem.sh";
import installScriptFile from "../../install/install.sh";
import reapSessionsScript from "../../install/reap-sessions.sh";
import redeemNodeScript from "../../install/redeem.mjs";
import bridgeProxyScript from "../../install/bridge-proxy.py";
import type { Env, RateLimiter } from "./env";

export { HostDO } from "./durable-objects/host";
export { AgentDO } from "./durable-objects/agent";
export { ChallengeDO } from "./durable-objects/challenge";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await route(request, env);
    } catch (e) {
      console.error("worker error", { message: String(e) });
      return errorResponse(ERR.INTERNAL, "internal error");
    }
  },
} satisfies ExportedHandler<Env>;

/** Hostnames that serve the home page rather than the API. */
const SITE_HOSTS = new Set(["grantd.dev", "www.grantd.dev"]);

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const origin = env.PUBLIC_ORIGIN || url.origin;
  const seg = url.pathname.split("/").filter(Boolean);

  // The apex is the home page. The protocol lives on api., so a visitor who
  // lands on a service path here is sent there rather than shown a 404 —
  // capability URLs are minted against PUBLIC_ORIGIN and should already point
  // at api., but a hand-edited one should still work.
  if (SITE_HOSTS.has(url.hostname)) {
    if (request.method === "GET" && seg.length === 0) {
      return textResponse(docsMarkdown(origin), 200, "text/markdown; charset=utf-8");
    }
    return Response.redirect(`${origin}${url.pathname}${url.search}`, 308);
  }

  if (request.method === "GET" && seg.length === 0) {
    return textResponse(docsMarkdown(origin), 200, "text/markdown; charset=utf-8");
  }
  if (request.method === "GET" && seg[0] === "health") {
    return jsonResponse({ ok: true, protocol_version: 1 });
  }
  if (request.method === "GET" && seg[0] === "redeem.sh") {
    return scriptResponse(redeemScript);
  }
  // The Node client, for sandboxes that have a JavaScript runtime and no
  // openssl or ssh-keygen.
  if (request.method === "GET" && seg[0] === "redeem.mjs") {
    return scriptResponse(redeemNodeScript);
  }
  // A diagnostic echo. An agent sandbox can use it to find out whether its
  // egress carries WebSocket frames intact, which decides whether a WebSocket
  // transport could ever reach a host from there. It echoes each frame back
  // unchanged and keeps text and binary distinct. It holds no state, reads no
  // grant, and can be removed once that question is settled.
  if (request.method === "GET" && seg[0] === "ws-echo") {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return errorResponse(ERR.BAD_REQUEST, "this endpoint requires a websocket upgrade", 426);
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
    server.accept();
    server.addEventListener("message", (event: MessageEvent) => {
      try {
        server.send(event.data);
      } catch {
        // A closing socket is not an error worth reporting here.
      }
    });
    return new Response(null, { status: 101, webSocket: client });
  }
  // The ProxyCommand shim, for a visitor whose sandbox has no raw TCP egress.
  // Served from the single copy in install/, like the redeemers, so the script
  // a visitor runs is the one the test suite exercises.
  if (request.method === "GET" && seg[0] === "bridge-proxy.py") {
    return scriptResponse(bridgeProxyScript, "text/x-python; charset=utf-8");
  }
  // The session reaper, fetched by install.sh. Served from the single copy in
  // install/ for the same reason as the redeemers.
  if (request.method === "GET" && seg[0] === "reap-sessions.sh") {
    return scriptResponse(reapSessionsScript);
  }
  if (request.method === "GET" && seg[0] === "install") {
    return scriptResponse(installScriptFile);
  }

  // Capability landing page. The secret is in the URL fragment, so it never
  // reaches this handler. Nothing here reads or echoes a query string.
  if (request.method === "GET" && seg[0] === "g" && seg.length === 3) {
    const [, hostId, grantId] = seg;
    if (!HOST_ID_RE.test(hostId) || !GRANT_ID_RE.test(grantId)) {
      return errorResponse(ERR.BAD_REQUEST, "malformed capability url");
    }
    return textResponse(grantInstructions(origin, hostId, grantId));
  }

  // Release artifacts from R2. Read-only. The release signing key is not on Cloudflare.
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

    const reg = body.registration as Record<string, unknown> | undefined;
    const challengeId = typeof reg?.challenge_id === "string" ? reg.challenge_id : "";
    const agentId = typeof reg?.agent_id === "string" ? reg.agent_id : "";
    const powNonce = typeof reg?.pow_nonce === "string" ? reg.pow_nonce : "";
    if (!AGENT_ID_RE.test(agentId)) {
      return errorResponse(ERR.BAD_REQUEST, "malformed agent_id");
    }
    if (!CHALLENGE_ID_RE.test(challengeId)) {
      return errorResponse(ERR.BAD_REQUEST, "malformed challenge_id");
    }

    // Consume the challenge first. If registration then fails, the challenge
    // is still spent. A failed attempt costs the caller a fresh proof of work.
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
        // Built fresh, so nothing the caller sent reaches the object as its
        // own address. See CLIENT_IP_HEADER.
        const headers = new Headers({ "content-type": "application/json" });
        setClientIp(headers, request);
        init.headers = headers;
      }
      return await stub.fetch(new Request(`https://do/host/${hostId}`, init));
    }

    // Rendezvous upgrade. The headers carry the host's signature. The body is empty.
    if (rest.length === 1 && rest[0] === "connect" && request.method === "GET") {
      // The signature headers must reach the object intact, so these are the
      // caller's own headers. Overwrite the address header on the copy: a
      // host must not be able to name the address its record points at.
      const headers = new Headers(request.headers);
      setClientIp(headers, request);
      return await stub.fetch(
        new Request(`https://do/host/${hostId}/connect`, { method: "GET", headers }),
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
      if (request.method === "PUT") {
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
      // Two limiters for two attacks. The IP-keyed one stops one noisy
      // source. The grant-keyed one stops a distributed flood against one
      // capability, which wakes someone else's machine on every attempt.
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
      // Garbage is refused here, before a Durable Object is woken.
      if (!parseJsonObject(raw)) return errorResponse(ERR.BAD_REQUEST, "body must be a JSON object");
      // Forwarded verbatim. The host must verify the bytes the agent signed.
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

/** Reads the body as text. Rejects more than MAX_REQUEST_BYTES, measured in bytes. */
async function readRaw(request: Request): Promise<string | Response> {
  const declared = request.headers.get("content-length");
  if (declared && Number(declared) > MAX_REQUEST_BYTES) {
    return errorResponse(ERR.BAD_REQUEST, "request body too large", 413);
  }
  const text = await request.text();
  if (new TextEncoder().encode(text).length > MAX_REQUEST_BYTES) {
    return errorResponse(ERR.BAD_REQUEST, "request body too large", 413);
  }
  return text;
}

async function readJson(request: Request): Promise<Record<string, unknown> | Response> {
  const raw = await readRaw(request);
  if (raw instanceof Response) return raw;
  const parsed = parseJsonObject(raw);
  if (!parsed) return errorResponse(ERR.BAD_REQUEST, "body must be a JSON object");
  return parsed;
}

/**
 * Stamps the caller's address onto a request headed for a Durable Object.
 *
 * Always sets or deletes, never leaves what was there. CF-Connecting-IP is
 * set by Cloudflare itself, so its absence means the request did not arrive
 * through the edge and there is no address worth trusting.
 */
function setClientIp(headers: Headers, request: Request): void {
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) headers.set(CLIENT_IP_HEADER, ip);
  else headers.delete(CLIENT_IP_HEADER);
}

/**
 * Rate limit key for the caller's IP, or null when there is none.
 *
 * Null skips the limiter. A shared fallback bucket makes every caller
 * without the header share one limit. Cloudflare sets CF-Connecting-IP
 * itself, so its absence means "not behind Cloudflare".
 */
function clientKey(request: Request): string | null {
  return request.headers.get("CF-Connecting-IP");
}

/**
 * Applies a rate limiter if the binding exists. Fails open, so a broken
 * limiter does not take the service down, and logs ratelimit.unavailable
 * so a failing binding is visible.
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
