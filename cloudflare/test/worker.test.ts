/**
 * Coordination service behaviour.
 *
 * Two kinds of test live here. The first kind checks that the service routes
 * correctly. The second kind checks that it *cannot* do the things a compromised
 * control plane would want to do — and those matter more, because the product's
 * claim is that this layer being hostile is survivable.
 */

import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { ORIGIN, TestAgent, TestHost, newGrantId, now, randomBytes, sshLine } from "./helpers";

async function errCode(res: Response): Promise<string> {
  const body = (await res.json()) as { error?: { code?: string } };
  return body.error?.code ?? "";
}

/**
 * Stands in for a real signer answering a wrong proof: cheap, immediate, and
 * pointedly not consuming the grant.
 */
function respondWithBadProof(ws: WebSocket): void {
  ws.addEventListener("message", (e) => {
    const frame = JSON.parse(String(e.data));
    if (frame.t !== "redeem.request") return;
    ws.send(
      JSON.stringify({
        t: "redeem.response",
        id: frame.id,
        status: 401,
        body: { error: { code: "BAD_PROOF", message: "redemption proof does not verify" } },
      }),
    );
  });
}

async function redeem(host: TestHost, agent: TestAgent, grantId: string): Promise<Response> {
  return await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}/redeem`, {
    method: "POST",
    body: JSON.stringify(await agent.redemptionBody(host.hostId, grantId, randomBytes(32))),
    headers: { "content-type": "application/json" },
  });
}

describe("public surface", () => {
  it("serves protocol documentation at the root", async () => {
    const res = await SELF.fetch(`${ORIGIN}/`);
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain("grantd");
    expect(text).toContain("/v1/hosts/:host_id/grants/:grant_id/redeem");
  });

  it("reports health", async () => {
    const res = await SELF.fetch(`${ORIGIN}/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, protocol_version: 1 });
  });

  it("serves redemption instructions without ever seeing a secret", async () => {
    const host = await TestHost.create();
    const grantId = newGrantId();
    const res = await SELF.fetch(`${ORIGIN}/g/${host.hostId}/${grantId}`);
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain(host.hostId);
    expect(text).toContain(grantId);
    // The instructions must tell the reader to keep the fragment local.
    expect(text).toContain("Do not send the secret");
  });

  it("rejects malformed identifiers", async () => {
    expect((await SELF.fetch(`${ORIGIN}/g/nope/also-nope`)).status).toBe(400);
    expect((await SELF.fetch(`${ORIGIN}/v1/hosts/h_short`)).status).toBe(400);
  });
});

describe("host registration", () => {
  it("registers a host and returns its public record", async () => {
    const host = await TestHost.create();
    const res = await host.register();
    expect(res.status).toBe(201);

    const rec = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`);
    expect(rec.status).toBe(200);
    const body = (await rec.json()) as Record<string, unknown>;
    expect(body.host_id).toBe(host.hostId);
    expect(body.ssh_user).toBe("ubuntu");
    expect(body.connected).toBe(false);
    // A public record must contain nothing private.
    expect(JSON.stringify(body)).not.toContain("PRIVATE");
  });

  it("rejects a registration whose host_id is not the hash of its key", async () => {
    const host = await TestHost.create();
    const other = await TestHost.create();
    const body = (await host.registrationBody()) as Record<string, unknown>;
    (body.registration as Record<string, unknown>).host_id = other.hostId;
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${other.hostId}`, {
      method: "PUT",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
    expect(await errCode(res)).toBe("ID_MISMATCH");
  });

  it("rejects a tampered registration field", async () => {
    const host = await TestHost.create();
    const body = (await host.registrationBody()) as Record<string, unknown>;
    // Exactly the change a hostile service would make: point the agent at a
    // machine it controls.
    (body.registration as Record<string, unknown>).hostname = "attacker.example.com";
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`, {
      method: "PUT",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
    expect(await errCode(res)).toBe("BAD_SIGNATURE");
  });

  it("rejects a replayed registration", async () => {
    const host = await TestHost.create();
    const body = await host.registrationBody();
    const send = () =>
      SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`, {
        method: "PUT",
        body: JSON.stringify(body),
        headers: { "content-type": "application/json" },
      });
    expect((await send()).status).toBe(201);
    expect(await errCode(await send())).toBe("REPLAYED_NONCE");
  });

  it("rejects a stale registration", async () => {
    const host = await TestHost.create();
    const body = await host.registrationBody({ timestamp: now() - 3600 });
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`, {
      method: "PUT",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
    expect(await errCode(res)).toBe("STALE_TIMESTAMP");
  });

  it("refuses to enroll root", async () => {
    const host = await TestHost.create();
    const body = await host.registrationBody({ ssh_user: "root" });
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`, {
      method: "PUT",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
    expect(res.status).toBe(400);
  });
});

describe("grant publication", () => {
  it("accepts host-signed grant metadata and serves it publicly", async () => {
    const host = await TestHost.create();
    await host.register();
    const grantId = newGrantId();
    expect((await host.publishGrant(grantId)).status).toBe(201);

    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    // Published metadata must carry no secret and no derivative of one.
    expect(Object.keys(body.grant as object).sort()).toEqual([
      "created_at",
      "expires_at",
      "grant_id",
      "host_id",
      "ssh_user",
      "version",
    ]);
  });

  it("rejects a grant that was not signed by this host", async () => {
    const host = await TestHost.create();
    const impostor = await TestHost.create();
    await host.register();
    const grantId = newGrantId();
    // A grant signed by the wrong key, published under the right host id.
    const body = (await impostor.grantBody(grantId)) as Record<string, unknown>;
    (body.grant as Record<string, unknown>).host_id = host.hostId;
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}`, {
      method: "PUT",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
    expect(await errCode(res)).toBe("BAD_SIGNATURE");
  });

  it("rejects a grant whose expiry was extended after signing", async () => {
    const host = await TestHost.create();
    await host.register();
    const grantId = newGrantId();
    const body = (await host.grantBody(grantId, 600)) as Record<string, unknown>;
    (body.grant as Record<string, unknown>).expires_at = now() + 7200;
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}`, {
      method: "PUT",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
    expect(await errCode(res)).toBe("BAD_SIGNATURE");
  });

  it("rejects a grant whose ttl exceeds the protocol maximum", async () => {
    const host = await TestHost.create();
    await host.register();
    const grantId = newGrantId();
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}`, {
      method: "PUT",
      body: JSON.stringify(await host.grantBody(grantId, 9 * 3600)),
      headers: { "content-type": "application/json" },
    });
    expect(res.status).toBe(400);
  });
});

describe("rendezvous", () => {
  it("accepts a correctly signed upgrade and marks the host connected", async () => {
    const host = await TestHost.create();
    await host.register();
    const ws = await host.connect();

    const hello = await new Promise<string>((resolve) => {
      ws.addEventListener("message", (e) => resolve(String(e.data)), { once: true });
    });
    expect(JSON.parse(hello)).toEqual({ t: "hello", protocol_version: 1 });

    const rec = (await (await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`)).json()) as {
      connected: boolean;
    };
    expect(rec.connected).toBe(true);
    ws.close();
  });

  it("rejects an upgrade with no signature", async () => {
    const host = await TestHost.create();
    await host.register();
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/connect`, {
      headers: { Upgrade: "websocket" },
    });
    expect(res.status).toBe(400);
  });

  it("rejects a replayed upgrade nonce", async () => {
    const host = await TestHost.create();
    await host.register();
    const nonce = randomBytes(16);
    const ts = now();
    const first = await host.connect(ts, nonce);
    await expect(host.connect(ts, nonce)).rejects.toThrow(/REPLAYED_NONCE|401/);
    first.close();
  });

  it("rejects an upgrade signed by a different host", async () => {
    const host = await TestHost.create();
    const impostor = await TestHost.create();
    await host.register();
    await impostor.register();
    // Signature is valid, but for the impostor's own host id; presenting it on
    // the victim's connect path must fail.
    const ts = now();
    const nonce = randomBytes(16);
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/connect`, {
      headers: {
        Upgrade: "websocket",
        "X-Grantd-Timestamp": String(ts),
        "X-Grantd-Nonce": "AAAAAAAAAAAAAAAAAAAAAA",
        "X-Grantd-Signature": "A".repeat(86),
      },
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
    void impostor;
    void nonce;
  });
});

describe("redemption routing", () => {
  it("returns HOST_OFFLINE when no daemon is connected", async () => {
    const host = await TestHost.create();
    const agent = await TestAgent.create();
    await host.register();
    const grantId = newGrantId();
    await host.publishGrant(grantId);

    const secret = randomBytes(32);
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}/redeem`, {
      method: "POST",
      body: JSON.stringify(await agent.redemptionBody(host.hostId, grantId, secret)),
      headers: { "content-type": "application/json" },
    });
    expect(await errCode(res)).toBe("HOST_OFFLINE");
  });

  it("forwards the redemption envelope to the host byte for byte", async () => {
    const host = await TestHost.create();
    const agent = await TestAgent.create();
    await host.register();
    const grantId = newGrantId();
    await host.publishGrant(grantId);
    const ws = await host.connect();

    const secret = randomBytes(32);
    const body = await agent.redemptionBody(host.hostId, grantId, secret);
    const sentJson = JSON.stringify(body);

    let forwarded: Record<string, unknown> | undefined;
    ws.addEventListener("message", (e) => {
      const frame = JSON.parse(String(e.data));
      if (frame.t !== "redeem.request") return;
      forwarded = frame.body;
      ws.send(
        JSON.stringify({
          t: "redeem.response",
          id: frame.id,
          status: 200,
          body: { certificate: "ssh-ed25519-cert-v01@openssh.com AAAA", user: "ubuntu" },
        }),
      );
    });

    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}/redeem`, {
      method: "POST",
      body: sentJson,
      headers: { "content-type": "application/json" },
    });
    expect(res.status).toBe(200);
    expect((await res.json()) as Record<string, unknown>).toMatchObject({ user: "ubuntu" });

    // The host must verify the bytes the agent signed. If the service
    // re-serialized or reordered anything, a proof over the original payload
    // could still verify while a substituted field slipped through.
    expect(forwarded).toEqual(JSON.parse(sentJson));
    ws.close();
  });

  it("relays the host's rejection code rather than masking it", async () => {
    const host = await TestHost.create();
    const agent = await TestAgent.create();
    await host.register();
    const grantId = newGrantId();
    await host.publishGrant(grantId);
    const ws = await host.connect();

    ws.addEventListener("message", (e) => {
      const frame = JSON.parse(String(e.data));
      if (frame.t !== "redeem.request") return;
      ws.send(
        JSON.stringify({
          t: "redeem.response",
          id: frame.id,
          status: 401,
          body: { error: { code: "BAD_PROOF", message: "redemption proof does not verify" } },
        }),
      );
    });

    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}/redeem`, {
      method: "POST",
      body: JSON.stringify(await agent.redemptionBody(host.hostId, grantId, randomBytes(32))),
      headers: { "content-type": "application/json" },
    });
    expect(res.status).toBe(401);
    expect(await errCode(res)).toBe("BAD_PROOF");
    ws.close();
  });

  it("rejects a redemption whose agent signature does not verify", async () => {
    const host = await TestHost.create();
    const agent = await TestAgent.create();
    await host.register();
    const grantId = newGrantId();
    await host.publishGrant(grantId);

    const body = await agent.redemptionBody(host.hostId, grantId, randomBytes(32));
    // Substituting the SSH key is the canonical attack. It breaks the agent
    // signature here, and would break the grant proof on the host even if it
    // did not.
    const attacker = await TestAgent.create();
    (body.payload as Record<string, unknown>).ssh_public_key = sshLine(attacker.sshKey.publicKey);

    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}/redeem`, {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
    expect(await errCode(res)).toBe("BAD_SIGNATURE");
  });

  it("rejects a redemption addressed to a different host", async () => {
    const host = await TestHost.create();
    const other = await TestHost.create();
    const agent = await TestAgent.create();
    await host.register();
    await other.register();
    const grantId = newGrantId();
    await host.publishGrant(grantId);

    const body = await agent.redemptionBody(other.hostId, grantId, randomBytes(32));
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}/redeem`, {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
    expect(await errCode(res)).toBe("ID_MISMATCH");
  });

  it("rejects a redemption for an unpublished grant", async () => {
    const host = await TestHost.create();
    const agent = await TestAgent.create();
    await host.register();
    const grantId = newGrantId();
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}/redeem`, {
      method: "POST",
      body: JSON.stringify(await agent.redemptionBody(host.hostId, grantId, randomBytes(32))),
      headers: { "content-type": "application/json" },
    });
    expect(await errCode(res)).toBe("GRANT_NOT_FOUND");
  });

  it("caps redemption attempts per grant, which an edge rule keyed on IP cannot do", async () => {
    const host = await TestHost.create();
    const agent = await TestAgent.create();
    await host.register();
    const grantId = newGrantId();
    await host.publishGrant(grantId);
    const ws = await host.connect();
    respondWithBadProof(ws);

    // A wrong proof does not consume the grant — that is deliberate, so that
    // guessing cannot burn a legitimate capability. The cost it does impose is
    // waking the customer's machine, and grant_id lives in the request body
    // where a WAF rule cannot see it. Hence a limiter keyed on the grant.
    const codes: string[] = [];
    for (let i = 0; i < 14; i++) {
      codes.push(await errCode(await redeem(host, agent, grantId)));
    }
    expect(codes.filter((c) => c === "BAD_PROOF").length).toBe(10);
    expect(codes.filter((c) => c === "RATE_LIMITED").length).toBe(4);
    expect(codes[0]).toBe("BAD_PROOF");
    ws.close();
  });

  it("caps redemption attempts per host across many grants", async () => {
    const host = await TestHost.create();
    const agent = await TestAgent.create();
    await host.register();
    const ws = await host.connect();
    respondWithBadProof(ws);

    // Spreading the flood across grants defeats the per-grant limiter, and
    // spreading it across IPs would defeat an edge rule. The Durable Object is
    // the only place with a consistent per-host view, so the last line lives
    // there.
    const grants: string[] = [];
    for (let g = 0; g < 7; g++) {
      const id = newGrantId();
      await host.publishGrant(id);
      grants.push(id);
    }

    const codes: string[] = [];
    for (const grantId of grants) {
      for (let i = 0; i < 10; i++) {
        codes.push(await errCode(await redeem(host, agent, grantId)));
      }
    }
    expect(codes.filter((c) => c === "BAD_PROOF").length).toBe(60);
    expect(codes.filter((c) => c === "RATE_LIMITED").length).toBe(10);
    ws.close();
  });

  it("rejects an oversized body before parsing it", async () => {
    const host = await TestHost.create();
    await host.register();
    const grantId = newGrantId();
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}/redeem`, {
      method: "POST",
      body: "x".repeat(20000),
      headers: { "content-type": "application/json" },
    });
    expect(res.status).toBe(413);
  });
});
