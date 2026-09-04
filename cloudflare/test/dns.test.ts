/**
 * Host DNS naming.
 *
 * The security-relevant tests here are the ones asserting that *no* call is
 * made: the point of handing this service a DNS credential is that a host can
 * only ever cause a write to its own derived label.
 */

import { env as testEnv, SELF } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { dnsConfig, hostRecordName, recordTypeFor } from "../src/dns";
import type { Env } from "../src/env";
import { ORIGIN, TestHost } from "./helpers";

/** cloudflare:test types `env` from generated bindings; this suite wants ours. */
const env = testEnv as unknown as Env;

const SUFFIX = "hosts.grantd.test";

/** A recorded call to the Cloudflare API. */
interface CfCall {
  method: string;
  url: string;
  body: Record<string, unknown> | undefined;
}

/**
 * Intercepts the Worker's outbound fetch. The pool runs the Worker in this
 * isolate, so a global spy catches it. Anything not aimed at the Cloudflare
 * API is passed through untouched.
 */
function interceptCloudflare(handler: (call: CfCall) => Response): CfCall[] {
  const calls: CfCall[] = [];
  const real = globalThis.fetch;
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: any, init?: any) => {
    const url = typeof input === "string" ? input : input.url;
    if (!url.includes("api.cloudflare.com")) return real(input, init);
    const call: CfCall = {
      method: init?.method ?? "GET",
      url,
      body: init?.body ? JSON.parse(init.body as string) : undefined,
    };
    calls.push(call);
    return handler(call);
  });
  return calls;
}

function cfJson(body: unknown, success = true): Response {
  return new Response(JSON.stringify({ success, result: body, errors: [] }), {
    headers: { "content-type": "application/json" },
  });
}

/** Registers a host, as the edge would: CF-Connecting-IP is set by Cloudflare. */
async function register(
  host: TestHost,
  hostname: string,
  headers: Record<string, string> = {},
): Promise<Response> {
  return await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`, {
    method: "PUT",
    body: JSON.stringify(await host.registrationBody({ hostname })),
    headers: { "content-type": "application/json", ...headers },
  });
}

/** The one name this service may write for a host. */
const nameFor = (host: TestHost) => `${host.hostId.slice(2)}.${SUFFIX}`;

afterEach(() => {
  vi.restoreAllMocks();
});

describe("configuration", () => {
  it("uses the test bindings, never the maintainer's .dev.vars", () => {
    // If this fails, the suite is one bad hostname away from writing records
    // in the real zone.
    expect(env.CF_DNS_TOKEN).toBe("test-token-not-a-real-credential");
    expect(env.HOST_ZONE_ID).toBe("00000000000000000000000000000000");
    expect(env.HOST_DNS_SUFFIX).toBe(SUFFIX);
  });

  it("is off unless all three parts are present", () => {
    const full = { CF_DNS_TOKEN: "t", HOST_ZONE_ID: "a".repeat(32), HOST_DNS_SUFFIX: "h.example.com" };
    expect(dnsConfig(full)).toBeDefined();
    expect(dnsConfig({ ...full, CF_DNS_TOKEN: undefined })).toBeUndefined();
    expect(dnsConfig({ ...full, HOST_ZONE_ID: undefined })).toBeUndefined();
    expect(dnsConfig({ ...full, HOST_DNS_SUFFIX: undefined })).toBeUndefined();
    expect(dnsConfig({ ...full, CF_DNS_TOKEN: "   " })).toBeUndefined();
  });

  it("refuses a malformed zone id or suffix", () => {
    const base = { CF_DNS_TOKEN: "t", HOST_ZONE_ID: "a".repeat(32), HOST_DNS_SUFFIX: "h.example.com" };
    expect(dnsConfig({ ...base, HOST_ZONE_ID: "nope" })).toBeUndefined();
    expect(dnsConfig({ ...base, HOST_DNS_SUFFIX: "single" })).toBeUndefined();
    expect(dnsConfig({ ...base, HOST_DNS_SUFFIX: "trailing.dot." })).toBeUndefined();
    expect(dnsConfig({ ...base, HOST_DNS_SUFFIX: "-lead.example.com" })).toBeUndefined();
    expect(dnsConfig({ ...base, HOST_DNS_SUFFIX: "a b.example.com" })).toBeUndefined();
  });
});

describe("name derivation", () => {
  it("builds the name from the host id alone", () => {
    const id = "h_" + "a".repeat(32);
    expect(hostRecordName(id, SUFFIX)).toBe(`${"a".repeat(32)}.${SUFFIX}`);
  });

  it("refuses anything that is not a host id", () => {
    expect(hostRecordName("a_" + "a".repeat(32), SUFFIX)).toBeUndefined();
    expect(hostRecordName("h_short", SUFFIX)).toBeUndefined();
    // Base32 has no 0, 1, 8 or 9, so a label that could smuggle a dot or a
    // hyphen cannot be a host id in the first place.
    expect(hostRecordName("h_" + "0".repeat(32), SUFFIX)).toBeUndefined();
    expect(hostRecordName("h_" + "a".repeat(31) + ".", SUFFIX)).toBeUndefined();
  });

  it("classifies addresses", () => {
    expect(recordTypeFor("203.0.113.7")).toBe("A");
    expect(recordTypeFor("2606:4700::1111")).toBe("AAAA");
    expect(recordTypeFor("999.0.0.1")).toBeUndefined();
    expect(recordTypeFor("not-an-address")).toBeUndefined();
    expect(recordTypeFor("")).toBeUndefined();
  });
});

describe("registration", () => {
  it("creates an unproxied record for a host that asked for a name", async () => {
    const host = await TestHost.create();
    const calls = interceptCloudflare((call) =>
      call.method === "POST" ? cfJson({ id: "rec1" }) : cfJson([]),
    );

    const res = await register(host, nameFor(host), { "CF-Connecting-IP": "203.0.113.7" });
    expect(res.status).toBe(201);
    expect((await res.json() as { dns_name: string }).dns_name).toBe(nameFor(host));

    const created = calls.find((c) => c.method === "POST");
    expect(created).toBeDefined();
    // The whole "direct SSH, never proxied" promise rests on this field.
    expect(created!.body).toMatchObject({
      type: "A",
      name: nameFor(host),
      content: "203.0.113.7",
      proxied: false,
    });
    // Scoped to the configured zone, and nothing else.
    expect(created!.url).toContain(`/zones/${env.HOST_ZONE_ID}/dns_records`);
  });

  it("updates in place when the name already has a record", async () => {
    const host = await TestHost.create();
    const calls = interceptCloudflare((call) =>
      call.method === "GET"
        ? cfJson([{ id: "existing", type: "A", name: nameFor(host), content: "198.51.100.1" }])
        : cfJson({ id: "existing" }),
    );

    await register(host, nameFor(host), { "CF-Connecting-IP": "203.0.113.9" });

    expect(calls.some((c) => c.method === "POST")).toBe(false);
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.url).toContain("/dns_records/existing");
    expect(put?.body).toMatchObject({ content: "203.0.113.9", proxied: false });
  });

  it("removes a stale record of the other family", async () => {
    const host = await TestHost.create();
    const calls = interceptCloudflare((call) =>
      call.method === "GET"
        ? cfJson([{ id: "v6", type: "AAAA", name: nameFor(host), content: "2606:4700::1" }])
        : cfJson({ id: "new" }),
    );

    await register(host, nameFor(host), { "CF-Connecting-IP": "203.0.113.7" });

    expect(calls.find((c) => c.method === "DELETE")?.url).toContain("/dns_records/v6");
  });

  it("writes nothing for a host enrolled with its own address", async () => {
    const host = await TestHost.create();
    const calls = interceptCloudflare(() => cfJson([]));

    const res = await register(host, "box.example.com", { "CF-Connecting-IP": "203.0.113.7" });
    expect(res.status).toBe(201);
    expect((await res.json() as { dns_name: null }).dns_name).toBeNull();
    expect(calls).toHaveLength(0);
  });
});

describe("a host cannot name itself anything it likes", () => {
  // The registration is signed, so the hostname field is genuinely the
  // host's. It still must not decide which record gets written.
  const forbidden = [
    "api.grantd.test",
    "grantd.test",
    `evil.${SUFFIX}`,
    `${"b".repeat(32)}.${SUFFIX}`, // another host's label
    "www.example.com",
  ];

  for (const hostname of forbidden) {
    it(`refuses to write ${hostname}`, async () => {
      const host = await TestHost.create();
      const calls = interceptCloudflare(() => cfJson([]));

      const res = await register(host, hostname, { "CF-Connecting-IP": "203.0.113.7" });
      expect(res.status).toBe(201);
      expect((await res.json() as { dns_name: null }).dns_name).toBeNull();
      expect(calls).toHaveLength(0);
    });
  }
});

describe("the address is the edge's, not the caller's", () => {
  it("ignores a client-supplied X-Grantd-Client-IP", async () => {
    const host = await TestHost.create();
    const calls = interceptCloudflare((call) =>
      call.method === "POST" ? cfJson({ id: "rec" }) : cfJson([]),
    );

    await register(host, nameFor(host), {
      "CF-Connecting-IP": "203.0.113.7",
      "X-Grantd-Client-IP": "192.0.2.66",
    });

    expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({ content: "203.0.113.7" });
  });

  it("writes nothing when the request did not arrive through the edge", async () => {
    const host = await TestHost.create();
    const calls = interceptCloudflare(() => cfJson([]));

    // No CF-Connecting-IP, and a spoofed internal header. Cloudflare sets the
    // real one itself, so its absence means there is no address to trust.
    const res = await register(host, nameFor(host), { "X-Grantd-Client-IP": "192.0.2.66" });
    expect(res.status).toBe(201);
    expect(calls).toHaveLength(0);
  });
});

describe("DNS never breaks enrollment", () => {
  it("registers the host even when the Cloudflare API fails", async () => {
    const host = await TestHost.create();
    interceptCloudflare(() => cfJson(null, false));

    const res = await register(host, nameFor(host), { "CF-Connecting-IP": "203.0.113.7" });
    expect(res.status).toBe(201);
    expect((await res.json() as { registered: boolean; dns_name: null }).registered).toBe(true);

    // And the host is fully usable.
    const record = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`);
    expect(record.status).toBe(200);
    expect((await record.json() as { dns_name: null }).dns_name).toBeNull();
  });

  it("registers the host even when the API throws", async () => {
    const host = await TestHost.create();
    const real = globalThis.fetch;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: any, init?: any) => {
      const url = typeof input === "string" ? input : input.url;
      if (url.includes("api.cloudflare.com")) throw new Error("network is down");
      return real(input, init);
    });

    const res = await register(host, nameFor(host), { "CF-Connecting-IP": "203.0.113.7" });
    expect(res.status).toBe(201);
  });
});

describe("the public record", () => {
  it("reports the managed name once one exists", async () => {
    const host = await TestHost.create();
    interceptCloudflare((call) => (call.method === "POST" ? cfJson({ id: "r" }) : cfJson([])));
    await register(host, nameFor(host), { "CF-Connecting-IP": "203.0.113.7" });

    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`);
    const body = await res.json() as { dns_name: string; hostname: string };
    expect(body.dns_name).toBe(nameFor(host));
    expect(body.hostname).toBe(nameFor(host));
  });
});
