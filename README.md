# grantd

**Let agents securely share their machines.**

[![ci](https://github.com/derekmeegan/grantd/actions/workflows/ci.yml/badge.svg)](https://github.com/derekmeegan/grantd/actions/workflows/ci.yml)
[![protocol](https://img.shields.io/badge/protocol-v1%20frozen-blue)](docs/whitepaper.md) [![whitepaper](https://img.shields.io/badge/whitepaper-grantd.dev-green)](https://grantd.dev/whitepaper)
[![platform](https://img.shields.io/badge/platform-linux%20%C2%B7%20openssh-lightgrey)](#requirements)

An agent working on a Linux box can hand another agent a shell on it — with no
account, no key exchange, and no human in the loop. The recipient needs nothing
installed: a URL, `curl`, and `ssh`.

A capability is redeemed once, and the certificate it issues is good for thirty
minutes by default. "Once" is the redemption, not the session: one certificate
opens as many connections as the visitor wants inside its window. When the
window closes, no new connection is possible, and a session still open is
closed by a reaper on the host.

The coordination service is a router, not a trust root. It never holds a
private key or a grant secret, and compromising it entirely is not enough to
obtain access to any machine.

---

## The whole thing in two commands

**The agent giving access**, on the machine it is sharing:

```sh
curl -s --unix-socket /run/grantd/owner/owner.sock \
  -X POST http://localhost/grants \
  -H 'content-type: application/json' -d '{"ttl_seconds":1800}'
```

```json
{ "grant_id": "g_4mmhs4dd4ww5qvnb",
  "expires_at": 1788283057,
  "capability_url": "https://api.grantd.dev/g/h_ubk4.../g_4mmh...#uJN2fx..." }
```

Send that URL to the recipient over any channel you trust.

**The agent receiving access**, anywhere on the internet:

```sh
curl -sO https://api.grantd.dev/redeem.sh
GRANTD_CAPABILITY='https://api.grantd.dev/g/h_ubk4.../g_4mmh...#uJN2fx...' sh redeem.sh
```

It verifies the host's signed registration, generates a throwaway SSH key,
registers an identity, redeems the capability, checks the certificate against
the host's CA, and prints the `ssh` command. Thirty minutes later the
certificate stops authenticating new connections, and the host closes any
session still running under it.

The URL can also be passed as an argument. On a shared machine prefer the
variable or stdin (`sh redeem.sh -`), because other users can read command
line arguments.

## Why

Every other way to do this is worse in a specific way.

**Sharing a private key** has no expiry and no attribution. You cannot take it
back, and you cannot tell afterwards who used it.

**Adding an `authorized_keys` entry** requires the recipient to already have a
key you trust, and someone has to remember to remove it. Nobody ever does.

**Teleport, Boundary, Cloudflare Access, step-ca** all issue short-lived SSH
certificates and all do it well — but every one assumes an identity provider, an
admin who configured a role, and a principal that existed in a directory
beforehand. That is the right model for employees. It does not describe an agent
that was created ten minutes ago and needs a shell for twenty.

grantd is for the case where the recipient has no account anywhere, is unknown
to everyone thirty seconds before connecting, and should be unknown again an
hour later.

## How it works

```
   OWNER MACHINE                  grantd service               VISITING AGENT
   ┌──────────────┐                ┌──────────┐                ┌──────────────┐
   │ grantd       │◄──WSS─────────►│ Worker   │◄────HTTPS─────►│ ephemeral    │
   │  (network)   │                │ HostDO   │                │ SSH keypair  │
   │      │       │                │ AgentDO  │                │ agent id     │
   │  unix socket │                └──────────┘                └──────┬───────┘
   │      ▼       │                                                   │
   │ grant-signer │   host identity key                               │
   │  (no network)│   SSH CA key                                      │
   │      │       │   grant secrets                                   │
   └──────┼───────┘                                                   │
          ▼                                                           │
        sshd ◄──────────────── direct SSH, never proxied ─────────────┘
```

1. The host generates its own SSH CA at install time and tells `sshd` to trust
   it. The private key never leaves the machine.
2. Creating a grant mints a random 32-byte secret, stored locally. Only signed
   *public* metadata is published — never the secret.
3. The secret travels in the URL **fragment**. Browsers and HTTP clients do not
   transmit fragments, so the service receives the path and never the capability.
4. Redeeming proves possession by HMAC over the request, keyed with that secret.
   The host verifies it locally and signs an SSH certificate.
5. Before redeeming, the agent fetches the host's signed record, checks that
   the identity key in it hashes to the `host_id` its capability URL already
   names, and verifies the signature. It takes the address and the SSH host
   key from that record and pins the host key.
6. The agent connects **directly** to the host. SSH traffic never touches the
   coordination service.

### What the service never sees

| Stays on the host | Stays with the visiting agent |
|---|---|
| SSH CA private key | ephemeral SSH private key |
| host identity private key | agent identity private key |
| grant secrets | |

A compromised coordination plane — Workers, Durable Objects, deployment
credentials, all of it — cannot fabricate a grant, extend an expiry, substitute
an SSH key, change which account the certificate is for, cause a second
certificate to be issued, or send the visitor to a machine the host did not
name. Each of those is a test in
[`go/tests/adversarial`](go/tests/adversarial), run against a service written to
be actively malicious.

The visitor trusts the service for nothing. The host id in the capability URL
is a hash of the host's identity key, so the redeemer fetches the host's signed
registration, verifies it against that id, and takes the hostname, port, user,
and SSH CA from the signed record. The certificate it receives must come from
that CA, for its own key, for that user.

**What the service is trusted for.** Two things, and the README is explicit
about both. It delivers `install` and `redeem.sh` when you fetch them from the
service origin, and it routes traffic. If you do not want to trust it for code
delivery, take both scripts from a pinned release of this repository instead.
The installer then verifies every binary it runs against the release signature
embedded in it.

## Install

On the machine you want to share:

```sh
curl -sO https://api.grantd.dev/install
sudo bash install --origin https://api.grantd.dev \
  --ssh-user <an unprivileged account> --hostname <the address visitors dial>
```

If the machine has no stable address to hand out, swap `--hostname` for
`--dns-suffix` and let the service publish one for it:

```sh
sudo bash install --origin https://api.grantd.dev \
  --ssh-user <an unprivileged account> --dns-suffix hosts.example.com
```

The name is derived from the host id, so it is this machine's and no other's,
and the record is never proxied — SSH still goes direct. This requires the
service to be configured for it; see
[`cloudflare/README.md`](cloudflare/README.md#host-dns-naming).

### When the visitor has no raw TCP

Some sandboxes — Claude's among them — allow HTTP over TLS and nothing else.
A gateway there will carry a TLS handshake and reset a plaintext SSH
identification string, so no port helps: 22 is blocked and 443 is inspected.

For those, the host can serve the session over a WebSocket on 443:

```sh
sudo ./bridge.sh --email you@example.com
```

That installs nginx and certbot, obtains a certificate for the machine's
`--dns-suffix` name, and runs `grantd-bridge`, which copies bytes between a
WebSocket and `127.0.0.1:22` and does nothing else — the target is compiled
in, so no request can move it. Visitors need no new flags: `redeem.sh` probes
the direct path first, and falls back to the bridge only when it must.

The bridge changes the pipe, not the trust. TLS terminates on your host, so
the coordination service is still not in the path and still never sees a byte
of the session; the visitor still pins the host key and still presents a
certificate your CA issued. What does change is that sshd sees every bridged
session as coming from `127.0.0.1`, so per-source controls like fail2ban
cannot see a bridged visitor — nginx's connection and rate limits replace
them.

Fetching `install` from the service means trusting the service to deliver
that one script. If that is not acceptable, use
[`install/install.sh`](install/install.sh) from a tagged release of this
repository. Either way, the script verifies the release signature and every
binary hash before it runs anything, refuses to start if `sshd -t` already
fails, gates every `sshd` reload on `sshd -t`, and restores the previous SSH
configuration if any step fails. The signed manifest also binds the release
version, so an origin cannot serve an older release under a newer name.

`root` cannot be enrolled. A visiting agent's blast radius is bounded by the
account you choose, and enrolling `root` removes the bound.

Removal destroys the CA private key, after which no certificate it ever signed
is accepted again:

```sh
sudo ./uninstall.sh --yes
```

### Requirements

**Host:** Linux, systemd, OpenSSH with an ed25519 host key
(`/etc/ssh/ssh_host_ed25519_key.pub`, which every distribution generates on
install and `ssh-keygen -A` creates), `amd64` or `arm64`, outbound HTTPS.

**Visitor:** a path to the host's SSH port, plus either `curl`, `ssh` and
OpenSSL 3.x, or Node 18 and an SSH client library.

That first requirement is the one that disqualifies most agent sandboxes, so it
is worth stating plainly. SSH is never proxied through the coordination
service, so the visitor must be able to open a connection to the host itself.
Raw outbound TCP satisfies this. So does an HTTP `CONNECT` proxy named in
`HTTPS_PROXY`, because `CONNECT` builds a byte pipe and SSH runs over it
unchanged. Hosts listed in `NO_PROXY` are reached directly, as curl does. Many sandboxes allow `CONNECT` only to port 443, which is why the
installer takes `--listen-port 443`.

Both redeemers check that path before they spend the grant and refuse with an
explanation rather than handing back a certificate that cannot be used.

If a sandbox has a JavaScript runtime and no package manager, use
[`install/redeem.mjs`](install/redeem.mjs). It needs no dependencies and no
binaries, not even `openssl` or `ssh-keygen`.

macOS ships LibreSSL as `openssl`, which has no Ed25519 at all. `redeem.sh`
looks for a capable binary in the usual places and says so plainly if there is
none; set `GRANTD_OPENSSL` to override.

## For agents

This is designed to be adopted without a human present, in both directions.

**If you were handed a capability URL**, fetch its path for instructions written
for you:

```sh
curl https://api.grantd.dev/g/<host_id>/<grant_id>
```

You get the exact requests to make, in plain text. There is no SDK, and
[`install/redeem.sh`](install/redeem.sh) is a reference implementation in POSIX
shell — if you would rather implement the protocol yourself,
[the whitepaper](docs/whitepaper.md) specifies every signed byte and
[`protocol/test-vectors/v1.json`](protocol/test-vectors/v1.json) lets you check
your work before talking to anything real.

Keep the part after `#`. It is the capability, the service cannot recover it for
you, and anyone who reads it has the access you were given.

Before redeeming, fetch `GET /v1/hosts/<host_id>` and verify it: the record must
name your `host_id`, the identity key in it must hash to that `host_id`, and the
signature must verify under that key. Take the address and the SSH host key
from the record and pin the host key when you connect. Both redeemers do this;
[`docs/whitepaper.md` §7.1](docs/whitepaper.md) specifies it. Skipping the pin hands
whoever resolves the address the choice of which machine you land on.

**If you want to grant access**, `POST /grants` on the owner Unix socket. That
socket is reachable only by the enrolled account on that machine — there is no
remote endpoint that creates grants, deliberately. You can only share a machine
you are already on.

**What registration is worth:** you must register an identity to redeem, and it
costs a proof of work. It is an abuse control, not a security boundary, and it
cannot be more than that — the signer that actually decides has no network and
no registry to consult. Authority comes only from the grant secret.

## Security model

Stated as invariants, each one tested:

1. The SSH CA private key never leaves the host.
2. The host identity private key never leaves the host.
3. The visiting agent's SSH private key never leaves the visiting agent.
4. Compromise of the coordination service, its database, and its deployment
   credentials is insufficient to mint a certificate.
5. A compromised service cannot substitute its own SSH public key into a
   redemption.
6. Grants are redeemed once, expiry is enforced by the host, and the host is
   authoritative over its own copy of every field.
7. The network-facing daemon cannot read either private key. It runs as a
   separate user with `/etc/grantd`, the signer's state, and the owner socket
   hidden from it. The daemon socket has no route that creates a grant or
   signs arbitrary bytes. The signer itself runs with no network at all.
8. The visitor accepts only a hostname, port, user, and certificate that the
   host signed, either directly (the registration) or through its CA (the
   certificate), and pins the SSH host key the host published in that same
   signed record. A compromised service can refuse to route a visitor; it
   cannot send one to a machine it controls — not even by pointing a name
   it resolves at a machine of its own, because the key does not match.

Invariants 1–7 protect the host from the service. Invariant 8 protects the
visitor from it. The two halves of invariant 8 do different jobs: the
certificate proves the visitor to the host, and the pinned host key proves the
host to the visitor. For an agent, the second matters as much as the first — a
shell on an attacker's box is an attacker-controlled input channel into
whatever the agent does next.

The rendezvous protocol has five message types and no generic RPC frame. There
is no message that carries a command, a path, or a filename, and there will not
be one.

## Testing

| Suite | Environment | Covers |
|---|---|---|
| `cd go && go test ./...` | — | canonical encoding, signer, a hostile coordination service |
| `cd cloudflare && npm test` | Miniflare | Worker routing, Durable Objects, cross-language vectors |
| `tests/e2e/run.sh` | two containers | capability URL to SSH session, driven only by `curl` and POSIX `sh` |
| `tests/install/run.sh` | Docker + systemd | install, sandbox, uninstall, SSH survival |
| `tests/install/release.sh` | Docker + systemd | install from signed artifacts; tampered and wrongly-signed releases |
| `tests/vm/run.sh` | Lima VM, Ubuntu LTS | **reboot**, unprivileged sandbox, host offline and back |
| `tests/remote/run.sh` | a host you supply | a real network path between visitor and host |
| `tests/remote/digitalocean.sh` | throwaway droplet | the above, provisioned and destroyed automatically |
| `.github/workflows/ci.yml` | real amd64 VM | the installer run natively; the systemd sandbox on amd64 |

The protocol has three independent implementations — Go, TypeScript, POSIX
shell — and all three are checked against the same frozen vectors rather than
against each other. Two implementations that only ever talk to each other can be
wrong in the same way forever.

The last suite needs a machine with an address a stranger can route to, which no
container and no Cloudflare product can provide. Workers do accept inbound TCP
now, but that path runs through Spectrum, and the property under test is
precisely that Cloudflare is *not* in the path.

```sh
DIGITALOCEAN_TOKEN=dop_v1_... tests/remote/digitalocean.sh
```

About a cent, about five minutes, destroys everything on any exit path.

## FAQ

**What can the visiting agent do once connected?** Anything that account can do.
V1 has no command restrictions and no session recording. The bound is the
account you enrolled and the certificate's lifetime. It cannot mint further
grants: the owner socket admits one uid, and `--owner-user` must not be the
account visitors log in as — the installer refuses to finish otherwise, and
checks by trying it. If that account has `sudo`,
so does your visitor — that is your machine's existing policy, not something
grantd grants.

**Can I self-host the coordination service?** Yes. It is a Cloudflare Worker in
[`cloudflare/`](cloudflare); `npm run deploy` puts it on your own account. The
host only needs `--origin` pointed at it. Since the service is not trusted, who
runs it matters less than it usually would.

**What happens if the service goes down?** Existing certificates keep working —
SSH never depended on it. No new grants can be redeemed until it returns.

**Why does a lost response burn the grant?** Because the alternative was a
retry path inside the transaction that makes grants single-use, and that is the
one function where a mistake means two keys get access. Grants are free to mint.

**Is the certificate revocable?** Not as a certificate — there is no CRL and
nothing to publish. What you can do is revoke the grant, which stops any
further redemption and makes the reaper close sessions running under it within
about fifteen seconds. Keep TTLs short: that is still the design.

**Does the deadline end an open session?** Yes, but not by itself. sshd checks
a certificate when it authenticates, so expiry alone stops new connections and
leaves a running session alone — that is OpenSSH's behaviour, not something
grantd chose. A `grantd-reaper` timer closes the gap: every fifteen seconds it
asks the signer which grants are done, matches them against the certificate ids
sshd logged at authentication, and signals those sessions. It only ever signals
a process sshd recorded as holding a grantd certificate, so an operator's own
session is never in scope.

## Status

V1: Linux hosts, OpenSSH, one enrolled non-root account per host, direct SSH
reachability. No relaying, no session recording, no command restrictions, no
Windows.

The protocol is frozen and the security model is tested against a deliberately
hostile coordination service. It has had one internal review, whose findings
are fixed in this tree, and no external security review — worth knowing before
you point it at something that matters.

Start with [the whitepaper](docs/whitepaper.md) — the whole security argument is
there. Then [`go/signer/redeem.go`](go/signer/redeem.go), the only code path
that can produce SSH access, and
[`go/signer/store/store.go`](go/signer/store/store.go), where single-use is
enforced.
