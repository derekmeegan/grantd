/** Protocol error codes and the uniform error envelope, docs/whitepaper.md §9. */

export const ERR = {
  BAD_REQUEST: "BAD_REQUEST",
  UNSUPPORTED_VERSION: "UNSUPPORTED_VERSION",
  ID_MISMATCH: "ID_MISMATCH",
  BAD_SIGNATURE: "BAD_SIGNATURE",
  STALE_TIMESTAMP: "STALE_TIMESTAMP",
  REPLAYED_NONCE: "REPLAYED_NONCE",
  HOST_NOT_FOUND: "HOST_NOT_FOUND",
  GRANT_NOT_FOUND: "GRANT_NOT_FOUND",
  AGENT_NOT_FOUND: "AGENT_NOT_FOUND",
  CHALLENGE_NOT_FOUND: "CHALLENGE_NOT_FOUND",
  CHALLENGE_CONSUMED: "CHALLENGE_CONSUMED",
  BAD_ANSWER: "BAD_ANSWER",
  HOST_OFFLINE: "HOST_OFFLINE",
  HOST_TIMEOUT: "HOST_TIMEOUT",
  GRANT_EXPIRED: "GRANT_EXPIRED",
  GRANT_REVOKED: "GRANT_REVOKED",
  GRANT_ALREADY_REDEEMED: "GRANT_ALREADY_REDEEMED",
  BAD_PROOF: "BAD_PROOF",
  RATE_LIMITED: "RATE_LIMITED",
  TOO_MANY_GRANTS: "TOO_MANY_GRANTS",
  /** Not a protocol code. Used for failures inside this service. */
  INTERNAL: "INTERNAL",
} as const;

export type ErrorCode = (typeof ERR)[keyof typeof ERR];

const STATUS: Record<string, number> = {
  BAD_REQUEST: 400,
  UNSUPPORTED_VERSION: 400,
  ID_MISMATCH: 400,
  BAD_SIGNATURE: 401,
  STALE_TIMESTAMP: 401,
  REPLAYED_NONCE: 401,
  BAD_ANSWER: 401,
  BAD_PROOF: 401,
  HOST_NOT_FOUND: 404,
  GRANT_NOT_FOUND: 404,
  AGENT_NOT_FOUND: 404,
  CHALLENGE_NOT_FOUND: 404,
  CHALLENGE_CONSUMED: 409,
  GRANT_ALREADY_REDEEMED: 409,
  GRANT_EXPIRED: 410,
  GRANT_REVOKED: 410,
  RATE_LIMITED: 429,
  TOO_MANY_GRANTS: 429,
  HOST_OFFLINE: 503,
  HOST_TIMEOUT: 504,
};

export function statusFor(code: string): number {
  return STATUS[code] ?? 500;
}

const BASE_HEADERS = { "x-content-type-options": "nosniff" };

export function errorResponse(code: string, message: string, status?: number): Response {
  return new Response(JSON.stringify({ error: { code, message } }), {
    status: status ?? statusFor(code),
    headers: { ...BASE_HEADERS, "content-type": "application/json; charset=utf-8" },
  });
}

export function jsonResponse(body: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...BASE_HEADERS, "content-type": "application/json; charset=utf-8", ...headers },
  });
}

export function textResponse(
  body: string,
  status = 200,
  contentType = "text/plain; charset=utf-8",
  extraHeaders: HeadersInit = {},
): Response {
  return new Response(body, {
    status,
    headers: { ...BASE_HEADERS, "content-type": contentType, ...extraHeaders },
  });
}

/**
 * Scripts that people pipe into a shell are served uncached. A cached copy
 * of install.sh or redeem.sh can be an old version, and the person who runs
 * it cannot tell.
 */
export function scriptResponse(
  body: string,
  contentType = "text/x-shellscript; charset=utf-8",
): Response {
  return textResponse(body, 200, contentType, {
    "cache-control": "no-store, must-revalidate",
  });
}
