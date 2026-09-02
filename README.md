# grantd

**Let agents securely share their machines.**

[![ci](https://github.com/derekmeegan/grantd/actions/workflows/ci.yml/badge.svg)](https://github.com/derekmeegan/grantd/actions/workflows/ci.yml)
[![protocol](https://img.shields.io/badge/protocol-v1%20frozen-blue)](protocol/v1.md)
[![platform](https://img.shields.io/badge/platform-linux%20%C2%B7%20openssh-lightgrey)](#requirements)

An agent working on a Linux box can hand another agent a shell on it — for
thirty minutes, once, with no account, no key exchange, and no human in the
loop. The recipient needs nothing installed: a URL, `curl`, and `ssh`.

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
  "capability_url": "https://grantd.example.workers.dev/g/h_ubk4.../g_4mmh...#uJN2fx..." }
```

Send that URL to the recipient over any channel you trust.

**The agent receiving access**, anywhere on the internet:

```sh
curl -sO https://grantd.example.workers.dev/redeem.sh
GRANTD_CAPABILITY='https://grantd.example.workers.dev/g/h_ubk4.../g_4mmh...#uJN2fx...' sh redeem.sh
```

It verifies the host's signed registration, generates a throwaway SSH key,
registers an identity, redeems the capability, checks the certificate against
the host's CA, and prints the `ssh` command. Thirty minutes later the
certificate expires and there is nothing to revoke.

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
5. The agent connects **directly** to the host. SSH traffic never touches the
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
curl -sO https://grantd.example.workers.dev/install
sudo bash install --origin https://grantd.example.workers.dev \
  --ssh-user <an unprivileged account> --hostname <the address visitors dial>
```

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

**Host:** Linux, systemd, OpenSSH, `amd64` or `arm64`, outbound HTTPS.
**Visitor:** `curl`, `ssh`, and OpenSSL 3.x.

macOS ships LibreSSL as `openssl`, which has no Ed25519 at all. `redeem.sh`
looks for a capable binary in the usual places and says so plainly if there is
none; set `GRANTD_OPENSSL` to override.

## For agents

This is designed to be adopted without a human present, in both directions.

**If you were handed a capability URL**, fetch its path for instructions written
for you:

```sh
curl https://grantd.example.workers.dev/g/<host_id>/<grant_id>
```

You get the exact requests to make, in plain text. There is no SDK, and
[`install/redeem.sh`](install/redeem.sh) is a reference implementation in POSIX
shell — if you would rather implement the protocol yourself,
[`protocol/v1.md`](protocol/v1.md) specifies every signed byte and
[`protocol/test-vectors/v1.json`](protocol/test-vectors/v1.json) lets you check
your work before talking to anything real.

Keep the part after `#`. It is the capability, the service cannot recover it for
you, and anyone who reads it has the access you were given.

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
6. Grants are single-use, expiry is enforced by the host, and the host is
   authoritative over its own copy of every field.
7. The network-facing daemon cannot read either private key. It runs as a
   separate user with `/etc/grantd`, the signer's state, and the owner socket
   hidden from it. The daemon socket has no route that creates a grant or
   signs arbitrary bytes. The signer itself runs with no network at all.
8. The visitor accepts only a hostname, port, user, and certificate that the
   host signed, either directly (the registration) or through its CA (the
   certificate). A compromised service cannot redirect a visitor.

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
account you enrolled and the certificate's lifetime. If that account has `sudo`,
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

**Is the certificate revocable?** No. It expires. Keep TTLs short — that is the
design, not a limitation to work around.

## Status

V1: Linux hosts, OpenSSH, one enrolled non-root account per host, direct SSH
reachability. No relaying, no session recording, no command restrictions, no
Windows.

The protocol is frozen and the security model is tested against a deliberately
hostile coordination service. It has had one internal review, whose findings
are fixed in this tree, and no external security review — worth knowing before
you point it at something that matters.

Start with [`protocol/v1.md`](protocol/v1.md) — the whole security argument is
there. Then [`go/signer/redeem.go`](go/signer/redeem.go), the only code path
that can produce SSH access, and
[`go/signer/store/store.go`](go/signer/store/store.go), where single-use is
enforced.
