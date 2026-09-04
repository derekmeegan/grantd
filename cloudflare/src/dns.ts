/**
 * Host DNS naming.
 *
 * A host enrolled with a DNS suffix gets one address record under it,
 * pointing at the address its machine reaches this service from. The name is
 * derived here from the host id and never read from the registration. That is
 * the whole security argument for handing this service a DNS credential: a
 * host can only ever cause a write to its own 32-character label, so an
 * enrolled machine cannot claim `api.`, the apex, or another host's name.
 *
 * Records are never proxied. Proxying an SSH address routes the session
 * through Cloudflare, and "direct SSH, never proxied" is a property the
 * protocol promises. `proxied: false` is set explicitly on every write rather
 * than left to the zone default, which an operator can change.
 *
 * DNS is convenience, not security. Every failure here is logged and
 * swallowed: a host that cannot get a name is still correctly registered, and
 * still reachable at whatever address it was enrolled with.
 */

const API = "https://api.cloudflare.com/client/v4";

/** Bounds a registration's wait on a third-party API. */
const DNS_TIMEOUT_MS = 5_000;

/** Short, because a host's address can change when it reconnects. */
const RECORD_TTL_S = 60;

/** The base32 label a host id carries after its "h_" prefix. */
const LABEL_RE = /^[a-z2-7]{32}$/;

/**
 * A DNS suffix this service will write under. Lowercase labels, at least two
 * of them, no trailing dot. Deliberately narrow: this string becomes part of
 * a name we create records for.
 */
const SUFFIX_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;

export interface DnsConfig {
  token: string;
  zoneId: string;
  suffix: string;
}

/**
 * The DNS configuration, or undefined when host naming is switched off.
 *
 * All three parts must be present. A half-configured deployment does nothing
 * rather than guessing, so adding the vars without the secret — or the secret
 * without the vars — is inert instead of half-working.
 */
export function dnsConfig(env: {
  CF_DNS_TOKEN?: string;
  HOST_ZONE_ID?: string;
  HOST_DNS_SUFFIX?: string;
}): DnsConfig | undefined {
  const token = env.CF_DNS_TOKEN?.trim();
  const zoneId = env.HOST_ZONE_ID?.trim();
  const suffix = env.HOST_DNS_SUFFIX?.trim().toLowerCase();
  if (!token || !zoneId || !suffix) return undefined;
  if (!/^[0-9a-f]{32}$/.test(zoneId)) return undefined;
  if (!SUFFIX_RE.test(suffix)) return undefined;
  return { token, zoneId, suffix };
}

/**
 * The one name this service may write for a host.
 *
 * Derived from the host id, which is a hash of the host's identity key. The
 * registration's `hostname` field is not consulted: it is host-supplied, and
 * trusting it would let any enrolled machine point any name in the zone
 * wherever it liked.
 */
export function hostRecordName(hostId: string, suffix: string): string | undefined {
  if (!hostId.startsWith("h_")) return undefined;
  const label = hostId.slice(2);
  if (!LABEL_RE.test(label)) return undefined;
  return `${label}.${suffix}`;
}

/** "A" for an IPv4 literal, "AAAA" for IPv6, undefined for anything else. */
export function recordTypeFor(ip: string): "A" | "AAAA" | undefined {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    return ip.split(".").every((o) => Number(o) <= 255 && String(Number(o)) === o) ? "A" : undefined;
  }
  // Deliberately loose on IPv6 shape. The value comes from CF-Connecting-IP,
  // which Cloudflare sets; this rejects obvious junk, not every malformed form.
  if (/^[0-9a-fA-F:]{2,45}$/.test(ip) && ip.includes(":")) return "AAAA";
  return undefined;
}

interface CfRecord {
  id: string;
  type: string;
  name: string;
  content: string;
  proxied?: boolean;
}

async function cf(
  cfg: DnsConfig,
  path: string,
  init: RequestInit = {},
): Promise<{ ok: boolean; result: unknown; errors: unknown }> {
  const res = await fetch(`${API}/zones/${cfg.zoneId}${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${cfg.token}`,
      "content-type": "application/json",
      ...(init.headers as Record<string, string> | undefined),
    },
    signal: AbortSignal.timeout(DNS_TIMEOUT_MS),
  });
  const body = (await res.json().catch(() => ({}))) as {
    success?: boolean;
    result?: unknown;
    errors?: unknown;
  };
  return { ok: res.ok && body.success === true, result: body.result, errors: body.errors };
}

/**
 * Points `name` at `ip`, unproxied, creating or updating as needed.
 *
 * Also removes an address record of the other family for the same name, so a
 * machine that moves from IPv4 to IPv6 does not leave a stale record behind
 * that resolvers may hand out instead.
 */
export async function syncHostRecord(
  cfg: DnsConfig,
  name: string,
  ip: string,
): Promise<{ ok: true; type: "A" | "AAAA" } | { ok: false; reason: string }> {
  const type = recordTypeFor(ip);
  if (!type) return { ok: false, reason: "unusable client address" };

  const listed = await cf(cfg, `/dns_records?name=${encodeURIComponent(name)}&per_page=100`);
  if (!listed.ok) return { ok: false, reason: `list failed: ${JSON.stringify(listed.errors)}` };
  const existing = (Array.isArray(listed.result) ? listed.result : []) as CfRecord[];

  const body = JSON.stringify({ type, name, content: ip, ttl: RECORD_TTL_S, proxied: false });
  const mine = existing.find((r) => r.type === type);

  const written = mine
    ? await cf(cfg, `/dns_records/${mine.id}`, { method: "PUT", body })
    : await cf(cfg, "/dns_records", { method: "POST", body });
  if (!written.ok) return { ok: false, reason: `write failed: ${JSON.stringify(written.errors)}` };

  // A record of the other family for this same name would still be handed out.
  for (const stale of existing) {
    if ((stale.type === "A" || stale.type === "AAAA") && stale.type !== type) {
      await cf(cfg, `/dns_records/${stale.id}`, { method: "DELETE" }).catch(() => undefined);
    }
  }
  return { ok: true, type };
}

/**
 * Header the Worker uses to hand a Durable Object the caller's address.
 *
 * A Durable Object does not see CF-Connecting-IP, so the router copies it
 * across. The router always sets or deletes this header on the requests it
 * builds, so a value a client supplied can never survive into the object.
 */
export const CLIENT_IP_HEADER = "X-Grantd-Client-IP";
