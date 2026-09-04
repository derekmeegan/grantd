/**
 * Coordination service behaviour.
 *
 * Two kinds of test live here. The first kind checks that the service routes
 * correctly. The second kind checks that it cannot do the things a hostile
 * control plane wants to do. The second kind matters more.
 */

import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { b64uDecode, b64uEncode } from "../src/crypto/encoding";
import { hostId as deriveHostId, verifyEd25519 } from "../src/crypto/ids";
import { canonicalHostConnect, canonicalHostRegistration, parseHostRegistration } from "../src/protocol";
import {
  ORIGIN,
  TestAgent,
  TestHost,
  newGrantId,
  now,
  randomBytes,
  sign,
  solvePow,
  sshLine,
} from "./helpers";

/** Frames carry opaque bytes, so a test host encodes its answers the same way. */
function encodeBody(value: unknown): string {
  return b64uEncode(new TextEncoder().encode(JSON.stringify(value)));
}

function decodeBody(b64: string): unknown {
  return JSON.parse(new TextDecoder().decode(b64uDecode(b64)));
}

async function errCode(res: Response): Promise<string> {
  const body = (await res.json()) as { error?: { code?: string } };
  return body.error?.code ?? "";
}

type Frame = { t: string; id: string };

/** Answers every redeem.request on the socket with the frames that `reply` returns. */
function respondWith(ws: WebSocket, reply: (frame: Frame) => unknown[]): void {
  ws.addEventListener("message", (e) => {
    const frame = JSON.parse(String(e.data)) as Frame;
    if (frame.t !== "redeem.request") return;
    for (const out of reply(frame)) ws.send(JSON.stringify(out));
  });
}

function badProofFrame(id: string): unknown {
  return {
    t: "redeem.response",
    id,
    status: 401,
    body_b64: encodeBody({ error: { code: "BAD_PROOF", message: "redemption proof does not verify" } }),
  };
}

function issuedFrame(id: string): unknown {
  return {
    t: "redeem.response",
    id,
    status: 200,
    body_b64: encodeBody({ certificate: "ssh-ed25519-cert-v01@openssh.com AAAA", user: "ubuntu" }),
  };
}

/** A signer that answers a wrong proof: cheap, immediate, and not consuming the grant. */
function respondWithBadProof(ws: WebSocket): void {
  respondWith(ws, (f) => [badProofFrame(f.id)]);
}

async function redeemRaw(host: TestHost, grantId: string, body: string): Promise<Response> {
  return await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}/redeem`, {
    method: "POST",
    body,
    headers: { "content-type": "application/json" },
  });
}

async function redeem(host: TestHost, agent: TestAgent, grantId: string): Promise<Response> {
  const body = await agent.redemptionBody(host.hostId, grantId, randomBytes(32));
  return await redeemRaw(host, grantId, JSON.stringify(body));
}

/** A registered host with one published grant. */
async function hostWithGrant(): Promise<{ host: TestHost; grantId: string }> {
  const host = await TestHost.create();
  await host.register();
  const grantId = newGrantId();
  await host.publishGrant(grantId);
  return { host, grantId };
}

/** Records whether a redeem.request ever arrives on the socket. */
function wakeDetector(ws: WebSocket): () => boolean {
  let woken = false;
  ws.addEventListener("message", (e) => {
    if (JSON.parse(String(e.data)).t === "redeem.request") woken = true;
  });
  return () => woken;
}

const settle = () => new Promise((r) => setTimeout(r, 100));

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
    expect(text).toContain("Do not send the secret");
  });

  it("serves the bridge ProxyCommand shim, uncached", async () => {
    const res = await SELF.fetch(`${ORIGIN}/bridge-proxy.py`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/x-python");
    // A cached copy of a script someone pipes into an interpreter can be an
    // old version, and the person running it cannot tell.
    expect(res.headers.get("cache-control")).toContain("no-store");
    const text = await res.text();
    expect(text).toContain("ProxyCommand");
    // Served from the single copy in install/, so this is the script the
    // bridge tests exercise.
    expect(text).toContain("only wss:// is supported");
  });

  it("serves the session reaper, uncached", async () => {
    const res = await SELF.fetch(`${ORIGIN}/reap-sessions.sh`);
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toContain("no-store");
    const text = await res.text();
    // It must only ever signal a process sshd recorded as holding a grantd
    // certificate; a reaper that killed on any other basis could take out an
    // operator's own session.
    expect(text).toContain("ID grantd:");
    expect(text).toContain("expired-grants");
  });

  it("serves the home page on the apex and the API on api.", async () => {
    const home = await SELF.fetch("https://grantd.dev/");
    expect(home.status).toBe(200);
    expect(home.headers.get("content-type")).toContain("text/html");
    const html = await home.text();
    // People will want to read the source before trusting an installer.
    expect(html).toContain("github.com/derekmeegan/grantd");

    // The apex is not the protocol. A service path there is redirected, not
    // served, so there is only ever one origin minting capability URLs.
    const stray = await SELF.fetch("https://grantd.dev/health", { redirect: "manual" });
    expect(stray.status).toBe(308);
    expect(stray.headers.get("location")).toContain("/health");

    // The API host keeps its documentation root.
    const api = await SELF.fetch(`${ORIGIN}/health`);
    expect(api.status).toBe(200);
  });

  it("rejects malformed identifiers", async () => {
    expect((await SELF.fetch(`${ORIGIN}/g/nope/also-nope`)).status).toBe(400);
    expect((await SELF.fetch(`${ORIGIN}/v1/hosts/h_short`)).status).toBe(400);
  });

  it("answers HOST_NOT_FOUND for an unregistered host", async () => {
    const host = await TestHost.create();
    expect(await errCode(await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`))).toBe("HOST_NOT_FOUND");
    expect(
      await errCode(await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${newGrantId()}`)),
    ).toBe("HOST_NOT_FOUND");
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
    expect(JSON.stringify(body)).not.toContain("PRIVATE");
  });

  it("echoes the last accepted registration with a signature a visitor can verify", async () => {
    const host = await TestHost.create();
    expect((await host.register()).status).toBe(201);
    // A second registration updates the record. The echo must be the newest one.
    const update = await host.registrationBody({ hostname: "moved.example.com" });
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`, {
      method: "PUT",
      body: JSON.stringify(update),
      headers: { "content-type": "application/json" },
    });
    expect(res.status).toBe(200);

    const body = (await (await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`)).json()) as {
      registration: Record<string, unknown>;
      signature: string;
      hostname: string;
    };
    expect(body.hostname).toBe("moved.example.com");
    expect(body.registration).toEqual((update as { registration: unknown }).registration);
    expect(Object.keys(body.registration).sort()).toEqual([
      "host_id",
      "hostname",
      "identity_public_key",
      "nonce",
      "ssh_ca_public_key",
      "ssh_host_public_key",
      "ssh_port",
      "ssh_user",
      "timestamp",
      "version",
    ]);
    expect(body.registration.ssh_host_public_key).toBe(host.hostKeyLine);

    // Verify the way a visitor does: from the parsed fields, under the identity key.
    const reg = parseHostRegistration(body.registration);
    expect(await deriveHostId(reg.identity_public_key)).toBe(host.hostId);
    expect(
      await verifyEd25519(reg.identity_public_key, canonicalHostRegistration(reg), b64uDecode(body.signature)),
    ).toBe(true);
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

  it("rejects a registration carrying an unusable host key", async () => {
    const host = await TestHost.create();
    for (const bad of ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB", `${host.hostKeyLine} root@box`, "", "ssh-ed25519"]) {
      const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`, {
        method: "PUT",
        body: JSON.stringify(await host.registrationBody({ ssh_host_public_key: bad })),
        headers: { "content-type": "application/json" },
      });
      expect(await errCode(res), `host key ${JSON.stringify(bad)} was accepted`).toBe("BAD_REQUEST");
    }
  });

  it("rejects a registration whose host key was swapped after signing", async () => {
    // The substitution a hostile service would make: leave the address alone
    // and point the pin at a machine it holds the key for.
    const host = await TestHost.create();
    const other = await TestHost.create();
    const body = (await host.registrationBody()) as Record<string, unknown>;
    (body.registration as Record<string, unknown>).ssh_host_public_key = other.hostKeyLine;
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}`, {
      method: "PUT",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
    expect(await errCode(res)).toBe("BAD_SIGNATURE");
  });

  it("rejects a tampered registration field", async () => {
    const host = await TestHost.create();
    const body = (await host.registrationBody()) as Record<string, unknown>;
    // The change a hostile service makes: point the agent at its own machine.
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
    const { host, grantId } = await hostWithGrant();
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    // Published metadata carries no secret and no derivative of one.
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

  it("rejects a grant created in the future", async () => {
    const host = await TestHost.create();
    await host.register();
    const grantId = newGrantId();
    // Signed and well formed. Only the creation time is wrong: ten years out.
    const res = await SELF.fetch(`${ORIGIN}/v1/hosts/${host.hostId}/grants/${grantId}`, {
      method: "PUT",
      body: JSON.stringify(await host.grantBody(grantId, 600, now() + 10 * 365 * 86400)),
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
    // A valid signature from the impostor's key over the victim's connect path.
    const ts = now();
    const nonce = randomBytes(16);
    const path = `/v1/hosts/${host.hostId}/connect`;
    const signature = await sign(
      impostor.identity,
      canonicalHostConnect({ version: 1n, host_id: host.hostId, path, timestamp: BigInt(ts), nonce }),
    );
    const res = await SELF.fetch(`${ORIGIN}${path}`, {
      headers: {
        Upgrade: "websocket",
        "X-Grantd-Timestamp": String(ts),
        "X-Grantd-Nonce": b64uEncode(nonce),
        "X-Grantd-Signature": b64uEncode(signature),
      },
    });
    expect(await errCode(res)).toBe("BAD_SIGNATURE");
  });

  it("replaces the first connection with the second and routes redemptions to it", async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    const first = await host.connect();
    const firstWoken = wakeDetector(first);
    const firstClosed = new Promise<number>((resolve) => {
      first.addEventListener("close", (e) => resolve(e.code));
    });

    const second = await host.connect();
    expect(await firstClosed).toBe(1012);
    respondWith(second, (f) => [issuedFrame(f.id)]);

    const res = await redeem(host, agent, grantId);
    expect(res.status).toBe(200);
    await settle();
    expect(firstWoken()).toBe(false);
    second.close();
  });

  it("fails a pending redemption with HOST_OFFLINE when the socket closes", { timeout: 10_000 }, async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    const ws = await host.connect();
    // The daemon dies mid-request. The redeemer must not wait for the full timeout.
    ws.addEventListener("message", (e) => {
      if (JSON.parse(String(e.data)).t === "redeem.request") ws.close(1001, "going away");
    });
    expect(await errCode(await redeem(host, agent, grantId))).toBe("HOST_OFFLINE");
  });
});

describe("redemption routing", () => {
  it("returns HOST_OFFLINE when no daemon is connected", async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    expect(await errCode(await redeem(host, agent, grantId))).toBe("HOST_OFFLINE");
  });

  it("forwards the redemption envelope to the host byte for byte", async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    const ws = await host.connect();

    const body = await agent.redemptionBody(host.hostId, grantId, randomBytes(32));
    const sentJson = JSON.stringify(body);

    let forwarded: Record<string, unknown> | undefined;
    ws.addEventListener("message", (e) => {
      const frame = JSON.parse(String(e.data));
      if (frame.t !== "redeem.request") return;
      forwarded = decodeBody(frame.body_b64) as Record<string, unknown>;
      ws.send(JSON.stringify(issuedFrame(frame.id)));
    });

    const res = await redeemRaw(host, grantId, sentJson);
    expect(res.status).toBe(200);
    expect((await res.json()) as Record<string, unknown>).toMatchObject({ user: "ubuntu" });

    // The host must verify the bytes the agent signed. A re-serialization
    // here lets a substituted field slip past a proof over the original.
    expect(forwarded).toEqual(JSON.parse(sentJson));
    ws.close();
  });

  it("relays a 64-bit certificate serial without losing precision", async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    const ws = await host.connect();

    // A serial is a random uint64. float64 cannot hold it. Opaque relay keeps it exact.
    const serial = "5177954190189569593";
    respondWith(ws, (f) => [
      {
        t: "redeem.response",
        id: f.id,
        status: 200,
        body_b64: b64uEncode(new TextEncoder().encode(`{"serial":${serial},"user":"ubuntu"}`)),
      },
    ]);

    const res = await redeem(host, agent, grantId);
    expect(res.status).toBe(200);
    // Compared as text. Parsing it here reintroduces the rounding.
    expect(await res.text()).toContain(`"serial":${serial}`);
    ws.close();
  });

  it("relays the host's rejection code rather than masking it", async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    const ws = await host.connect();
    respondWithBadProof(ws);

    const res = await redeem(host, agent, grantId);
    expect(res.status).toBe(401);
    expect(await errCode(res)).toBe("BAD_PROOF");
    ws.close();
  });

  it("rejects a redemption whose agent signature does not verify", async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    const body = await agent.redemptionBody(host.hostId, grantId, randomBytes(32));
    // Substituting the SSH key is the canonical attack. It breaks the agent
    // signature here, and the grant proof on the host.
    const attacker = await TestAgent.create();
    (body.payload as Record<string, unknown>).ssh_public_key = sshLine(attacker.sshKey.publicKey);
    expect(await errCode(await redeemRaw(host, grantId, JSON.stringify(body)))).toBe("BAD_SIGNATURE");
  });

  it("rejects a redemption that borrows a registered agent_id with a stranger's key", async () => {
    const { host, grantId } = await hostWithGrant();
    const victim = await TestAgent.registered();
    const stranger = await TestAgent.create();
    const ws = await host.connect();
    const woken = wakeDetector(ws);

    // Signed with the stranger's key, claiming the victim's id. The signature
    // verifies under the key in the payload. Only the derivation check stops it.
    const body = await stranger.redemptionBody(host.hostId, grantId, randomBytes(32), {
      agentId: victim.agentId,
    });
    expect(await errCode(await redeemRaw(host, grantId, JSON.stringify(body)))).toBe("ID_MISMATCH");
    await settle();
    expect(woken()).toBe(false);
    ws.close();
  });

  it("rejects a redemption addressed to a different host", async () => {
    const { host, grantId } = await hostWithGrant();
    const other = await TestHost.create();
    await other.register();
    const agent = await TestAgent.registered();
    const body = await agent.redemptionBody(other.hostId, grantId, randomBytes(32));
    expect(await errCode(await redeemRaw(host, grantId, JSON.stringify(body)))).toBe("ID_MISMATCH");
  });

  it("rejects a redemption for an unpublished grant", async () => {
    const host = await TestHost.create();
    await host.register();
    const agent = await TestAgent.registered();
    expect(await errCode(await redeem(host, agent, newGrantId()))).toBe("GRANT_NOT_FOUND");
  });

  it("rejects a malformed body and a missing proof before waking the host", async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    const ws = await host.connect();
    const woken = wakeDetector(ws);

    expect((await redeemRaw(host, grantId, "{not json")).status).toBe(400);
    expect((await redeemRaw(host, grantId, "null")).status).toBe(400);
    expect((await redeemRaw(host, grantId, "[]")).status).toBe(400);

    const body = await agent.redemptionBody(host.hostId, grantId, randomBytes(32));
    delete body.proof;
    expect(await errCode(await redeemRaw(host, grantId, JSON.stringify(body)))).toBe("BAD_REQUEST");

    await settle();
    expect(woken()).toBe(false);
    ws.close();
  });

  it("rejects an ssh_public_key that is not an ssh-ed25519 blob", async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    const lines = [
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7",
      "ssh-ed25519 AAAA",
      "ssh-ed25519 " + btoa("not a wire blob at all, just text"),
      agent.sshPublicKeyLine + " comment",
    ];
    for (const sshLineValue of lines) {
      const body = await agent.redemptionBody(host.hostId, grantId, randomBytes(32), { sshLine: sshLineValue });
      expect(await errCode(await redeemRaw(host, grantId, JSON.stringify(body)))).toBe("BAD_REQUEST");
    }
  });

  it("caps redemption attempts per grant, which an edge rule keyed on IP cannot do", { timeout: 60_000 }, async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    const ws = await host.connect();
    respondWithBadProof(ws);

    // A wrong proof does not consume the grant. It does wake the machine, and
    // grant_id is in the body where a WAF rule cannot see it.
    const codes: string[] = [];
    for (let i = 0; i < 14; i++) {
      codes.push(await errCode(await redeem(host, agent, grantId)));
    }
    expect(codes.filter((c) => c === "BAD_PROOF").length).toBe(10);
    expect(codes.filter((c) => c === "RATE_LIMITED").length).toBe(4);
    expect(codes[0]).toBe("BAD_PROOF");
    ws.close();
  });

  // 70 sequential redemptions through real Durable Objects. The default 5s
  // timeout fails on a slow CI runner.
  it("caps redemption attempts per host across many grants", { timeout: 120_000 }, async () => {
    const host = await TestHost.create();
    const agent = await TestAgent.registered();
    await host.register();
    const ws = await host.connect();
    respondWithBadProof(ws);

    // Spreading over grants defeats the per-grant limiter. Spreading over IPs
    // defeats an edge rule. The Durable Object has the per-host view.
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

  it("refuses an unregistered agent", async () => {
    const { host, grantId } = await hostWithGrant();
    const stranger = await TestAgent.create();
    expect(await errCode(await redeem(host, stranger, grantId))).toBe("AGENT_NOT_FOUND");
  });

  it("refuses an unregistered agent before waking the host", async () => {
    const { host, grantId } = await hostWithGrant();
    const stranger = await TestAgent.create();
    const ws = await host.connect();
    const woken = wakeDetector(ws);

    await redeem(host, stranger, grantId);
    await settle();
    expect(woken()).toBe(false);
    ws.close();
  });

  it("rejects an oversized body before parsing it", async () => {
    const host = await TestHost.create();
    await host.register();
    const res = await redeemRaw(host, newGrantId(), "x".repeat(20000));
    expect(res.status).toBe(413);
  });
});

describe("hostile host frames", () => {
  it("answers INTERNAL, not a hang, for a response with an impossible status", { timeout: 10_000 }, async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    const ws = await host.connect();
    respondWith(ws, (f) => [{ t: "redeem.response", id: f.id, status: 1000, body_b64: encodeBody({}) }]);
    const res = await redeem(host, agent, grantId);
    expect(res.status).toBe(500);
    expect(await errCode(res)).toBe("INTERNAL");
    ws.close();
  });

  it("answers INTERNAL for a response whose body is not base64url", { timeout: 10_000 }, async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    const ws = await host.connect();
    respondWith(ws, (f) => [{ t: "redeem.response", id: f.id, status: 200, body_b64: "not base64!!" }]);
    const res = await redeem(host, agent, grantId);
    expect(await errCode(res)).toBe("INTERNAL");
    ws.close();
  });

  it("drops a response for an unknown request id and still delivers the right one", async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    const ws = await host.connect();
    respondWith(ws, (f) => [badProofFrame("no-such-request"), issuedFrame(f.id)]);
    const res = await redeem(host, agent, grantId);
    expect(res.status).toBe(200);
    ws.close();
  });

  it("drops unknown frame types", async () => {
    const { host, grantId } = await hostWithGrant();
    const agent = await TestAgent.registered();
    const ws = await host.connect();
    respondWith(ws, (f) => [
      { t: "exec", id: f.id, cmd: "rm -rf /" },
      "this is not even json",
      { t: 42 },
      issuedFrame(f.id),
    ]);
    const res = await redeem(host, agent, grantId);
    expect(res.status).toBe(200);
    ws.close();
  });
});

describe("agent registration", () => {
  it("issues a challenge with a proof of work and no expected answer", async () => {
    const res = await SELF.fetch(`${ORIGIN}/v1/agent-challenges`, { method: "POST" });
    expect(res.status).toBe(201);
    const ch = (await res.json()) as Record<string, unknown>;
    expect(ch).toHaveProperty("challenge_id");
    expect(ch).toHaveProperty("pow");
    expect(ch).not.toHaveProperty("question");
    expect(ch).not.toHaveProperty("answer");
    expect(JSON.stringify(ch)).not.toContain("answer");
  });

  it("registers an agent that solves the proof of work", async () => {
    const a = await TestAgent.create();
    const res = await a.register();
    expect(res.status).toBe(201);
    const rec = await SELF.fetch(`${ORIGIN}/v1/agents/${a.agentId}`);
    expect(rec.status).toBe(200);
    // The record is public and holds nothing but a public key.
    const body = (await rec.json()) as Record<string, unknown>;
    expect(body.agent_id).toBe(a.agentId);
    expect(Object.keys(body).sort()).toEqual(["agent_id", "created_at", "last_seen_at", "public_key"]);
  });

  it("rejects a registration with a wrong proof of work", async () => {
    const a = await TestAgent.create();
    const chRes = await SELF.fetch(`${ORIGIN}/v1/agent-challenges`, { method: "POST" });
    const ch = (await chRes.json()) as { challenge_id: string };
    const res = await SELF.fetch(`${ORIGIN}/v1/agents`, {
      method: "POST",
      body: JSON.stringify(await a.registrationBody(ch.challenge_id, "not-a-solution")),
      headers: { "content-type": "application/json" },
    });
    expect(await errCode(res)).toBe("BAD_ANSWER");
  });

  it("rejects a malformed challenge_id without touching a challenge object", async () => {
    const a = await TestAgent.create();
    const res = await SELF.fetch(`${ORIGIN}/v1/agents`, {
      method: "POST",
      body: JSON.stringify(await a.registrationBody("../../etc/passwd", "0")),
      headers: { "content-type": "application/json" },
    });
    expect(res.status).toBe(400);
  });

  it("rejects a registration whose agent_id is not the hash of its key", async () => {
    const a = await TestAgent.create();
    const other = await TestAgent.create();
    const chRes = await SELF.fetch(`${ORIGIN}/v1/agent-challenges`, { method: "POST" });
    const ch = (await chRes.json()) as {
      challenge_id: string;
      pow: { prefix: string; difficulty_bits: number };
    };
    const nonce = await solvePow(ch.pow.prefix, ch.pow.difficulty_bits);
    const body = (await a.registrationBody(ch.challenge_id, nonce)) as Record<string, unknown>;
    (body.registration as Record<string, unknown>).agent_id = other.agentId;
    const res = await SELF.fetch(`${ORIGIN}/v1/agents`, {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
    expect(await errCode(res)).toBe("ID_MISMATCH");
  });

  it("consumes a challenge exactly once", async () => {
    const chRes = await SELF.fetch(`${ORIGIN}/v1/agent-challenges`, { method: "POST" });
    const ch = (await chRes.json()) as {
      challenge_id: string;
      pow: { prefix: string; difficulty_bits: number };
    };
    const nonce = await solvePow(ch.pow.prefix, ch.pow.difficulty_bits);

    const first = await TestAgent.create();
    const r1 = await SELF.fetch(`${ORIGIN}/v1/agents`, {
      method: "POST",
      body: JSON.stringify(await first.registrationBody(ch.challenge_id, nonce)),
      headers: { "content-type": "application/json" },
    });
    expect(r1.status).toBe(201);

    // One proof of work must not mint two registrations.
    const second = await TestAgent.create();
    const r2 = await SELF.fetch(`${ORIGIN}/v1/agents`, {
      method: "POST",
      body: JSON.stringify(await second.registrationBody(ch.challenge_id, nonce)),
      headers: { "content-type": "application/json" },
    });
    expect(await errCode(r2)).toBe("CHALLENGE_CONSUMED");
  });
});
