# grantd coordination Worker

Routing and rendezvous. Not a trust root.

```
Worker (router)
  ├── HostDO(host_id)        public record, published grant metadata, hibernating WebSocket
  ├── AgentDO(agent_id)      public key, nothing else
  └── ChallengeDO(id)        one registration proof-of-work challenge, consumed once
```

No D1. There is very little global relational state in V1, and what there is
partitions perfectly by host, agent, or challenge — which is exactly what a
Durable Object is. A global database earns its place when something needs to
list or search across those partitions (organizations, billing, an admin view);
none of that exists yet.

## Commands

```
npm install
npm run typecheck
npm test          # vitest, real Ed25519, real Durable Objects
npm run dev
npm run deploy
```

Behind a TLS-intercepting proxy, add
`--registry=https://registry.npmjs.org/ --cafile=/etc/ssl/cert.pem` to `npm`.

## Abuse controls

Four layers, each doing something the others cannot.

**1. Cloudflare WAF and platform rate limiting rules — dashboard, not code.**
These run in front of the Worker, cost nothing per request, and stop junk before
it becomes an invocation. They see only the HTTP surface: method, path, IP, ASN,
headers, bot score. Configure:

| Rule | Suggested |
|---|---|
| Per-IP rate limit on `/v1/*` | 120 requests / minute |
| Per-IP rate limit on `/v1/agent-challenges` | 20 / minute |
| Request body size on `/v1/*` | reject above 16 KB |
| Bot Fight Mode / managed rules | on, excluding `/v1/hosts/*/connect` |

Keep the rendezvous path out of aggressive bot rules: it is a long-lived
WebSocket from a server, which is exactly the shape a bot heuristic dislikes.

**2. Workers rate limiting bindings, keyed by IP** — `CHALLENGE_LIMITER`,
`REGISTRATION_LIMITER`, `REDEMPTION_LIMITER`. These pair with the registration
proof of work so that mass registration is expensive in two dimensions rather
than one.

**3. A Workers rate limiter keyed by grant** — `REDEMPTION_GRANT_LIMITER`. This
is the one an edge rule cannot express, because `grant_id` is in the request
body. It matters because a flood of wrong proofs against a single grant does
*not* burn the grant (the signer rolls the claim back), but every attempt wakes
the customer's machine over the rendezvous socket. Without a per-grant limit
that is a free amplification channel into someone else's box, and a distributed
attacker defeats any IP-keyed rule.

**4. Per-host counters in `HostDO`** — the last line, and the only layer with a
consistent per-host view: every redemption for a host lands in one object, so a
flood spread across many IPs *and* many grant ids still counts. `HostDO` caps
published grants at 64 and forwarded redemption attempts at 60 per minute. The
count is taken immediately before the socket send, because waking the machine is
the resource being protected; anything rejected earlier costs the customer
nothing.

The limiter helpers fail open — a broken binding should not take the service
down — but they log `ratelimit.unavailable` when they do, so a persistently
failing binding is visible rather than silently disabled forever.

`clientKey()` returns `null` rather than a constant when `CF-Connecting-IP` is
absent, and a null key skips the IP-keyed limiter. A shared fallback bucket
would mean that in any context without the header every caller in the world
shares one limit and throttles everyone else. Cloudflare sets that header itself
and overwrites any client-supplied value, so its absence means "not behind
Cloudflare", not "attacker stripped it".

None of this is SSH authorization. All four layers can fail completely and a
visiting agent still cannot obtain a certificate without the grant secret.

## Host DNS naming

Optional. A host enrolled with `--dns-suffix hosts.example.com` gets one
unproxied address record pointing at the address its machine connects from, so
an operator does not have to find and hand over a stable address per box.

```
"vars": {
  "HOST_ZONE_ID": "<zone id>",
  "HOST_DNS_SUFFIX": "hosts.example.com"
}
```

```
npx wrangler secret put CF_DNS_TOKEN     # never in wrangler.jsonc
```

The token is the first credential this service holds that reaches outside
itself, so its scope is the whole argument. Create it as a custom token with
**Zone → DNS → Edit** on that one zone and nothing else. What that buys: the
worst a total compromise of this Worker can do with it is point a name at the
wrong address. Pinning turns that into a refused connection rather than a
session with a stranger, because the visiting agent verifies the host
certificate against the CA in the grant — an address is not an identity here.

Two rules in `src/dns.ts` keep it that narrow, and both matter:

* **The record name is derived from the host id**, which is a hash of the
  host's identity key. It is never read from the registration. A host can only
  ever cause a write to its own 32-character label, so an enrolled machine
  cannot take over `api.`, the apex, or another host's name.
* **The record is written only when the host's *signed* hostname already is
  that derived name.** That is how a host asks for one. A host enrolled with
  its own address is left alone entirely — no call is made.

`proxied: false` is set explicitly on every write rather than left to the zone
default, which an operator can change. Proxying an SSH address would route the
session through Cloudflare, and "direct SSH, never proxied" is a property the
protocol promises. In the dashboard the record must show a grey cloud; an
orange one means that promise has quietly stopped being true.

All three settings must be present or the feature is off — a half-configured
deployment does nothing rather than guessing. Nothing here can fail an
enrollment: every DNS error is logged (`host.dns_failed`) and swallowed, and a
host that never gets a name is still registered, still connected, and still
reachable at whatever address it was enrolled with.

The suffix needs no record of its own. It exists so that an operator can
allowlist `*.hosts.example.com` without that covering `api.` or anything else
on the apex.

## What this Worker cannot do

The adversarial tests in `test/worker.test.ts` and `tests/adversarial/` assert
these directly, with a deliberately malicious service:

* It cannot fabricate a grant — publication requires a host signature.
* It cannot extend an expiry — `expires_at` is inside the signed grant, and the
  signer re-checks its own copy anyway.
* It cannot substitute an SSH public key — the key is covered by an HMAC keyed
  with a secret it never receives.
* It cannot change the SSH username — the principal comes from the host's local
  enrollment record, never from the request.
* It cannot cause a second certificate — single use is enforced in a SQLite
  transaction on the customer's machine.
* It cannot ask a host to do anything else — the rendezvous frame vocabulary is
  fixed, and there is no frame that carries a command, a path, or a filename.

## Registration is required, and is not a security boundary

An unregistered `agent_id` is refused with `AGENT_NOT_FOUND`, before the request
reaches the customer's machine, so reaching a host at all costs a proof of work.

It cannot be more than an abuse control, and the reason is structural: the
signer decides everything, and it has no network and no registry to consult. It
therefore cannot check registration, and a compromised coordination service
could skip the check. Nothing in the security argument rests on it.
