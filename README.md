# grantd

Temporary, single-use SSH access for agents.

A human with an agent on a Linux box says *"give another agent SSH access for 30
minutes."* The local agent mints a capability URL. The recipient's agent
generates a throwaway SSH key, redeems the capability, receives a short-lived
SSH certificate, and connects directly to the host.

The coordination service is a router, not a trust root.

```
   OWNER MACHINE                  grantd service                VISITING AGENT
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

## There is no client to install

Two binaries run on a host. Neither side of a grant needs anything else.

The owner mints a capability with curl over a Unix socket:

```
curl -s --unix-socket /run/grantd/owner/owner.sock \
  -X POST http://localhost/grants \
  -H 'content-type: application/json' -d '{"ttl_seconds":1800}'
```

The recipient redeems with curl, openssl and ssh-keygen. `install/redeem.sh` is
a POSIX shell reference implementation that does the whole flow in about 250
lines, and the test suite uses it rather than a Go client — so "no SDK required"
is a property the tests would catch losing, not a claim in a README.

## What the service never receives

| Stays on the customer machine | Stays with the visiting agent |
|---|---|
| SSH CA private key | ephemeral SSH private key |
| host identity private key | agent identity private key |
| grant secrets | |

Compromising the entire coordination plane — Workers, Durable Objects,
deployment credentials — is not sufficient to mint a certificate for any host.
Authority comes from an HMAC keyed by a secret that only ever travels in a URL
fragment, from the owner to the recipient, out of band.

## Layout

```
protocol/          frozen v1 spec and normative cross-language test vectors
go/                grantd (daemon), grant-signer (trust root)
cloudflare/        Worker + Durable Objects: routing and rendezvous only
install/           installer, uninstaller, systemd units
tests/             end-to-end and adversarial suites
web/               static landing page
```

## Reading order

1. `protocol/v1.md` — the whole security argument is in here.
2. `go/signer/redeem.go` — the only code path that can produce SSH access.
3. `go/signer/store/store.go` — `ClaimGrant`, where single-use is enforced.

## Testing

| Suite | Environment | What it covers |
|---|---|---|
| `go test ./...` | — | canonical encoding, signer, a hostile coordination service |
| `cloudflare && npm test` | Miniflare | Worker routing, Durable Objects, cross-language vectors |
| `tests/e2e/run.sh` | Docker, two containers | capability URL to SSH session, driven by curl and POSIX sh |
| `tests/install/run.sh` | Docker + systemd | install, sandbox, uninstall, SSH survival |
| `tests/install/release.sh` | Docker + systemd | install from a signed release; tampered and wrongly-signed artifacts |
| `tests/vm/run.sh` | **Lima VM, Ubuntu LTS** | **reboot**, unprivileged sandbox, daemon offline and back, service unreachable |
| `.github/workflows/ci.yml` | **real amd64 VM** | the installer run natively; the systemd sandbox on amd64 |
| `tests/remote/run.sh` | **a host you supply** | a real network path between visitor and host |
| `tests/remote/digitalocean.sh` | **a throwaway droplet** | the above, provisioned and destroyed automatically |

The VM suite exists because containers cannot reboot, and `protocol/v1.md` §12
makes claims that only a reboot can test. It also reaches the machine over SSH,
so "the installer must not brick sshd" is finally tested where breaking it
costs the test its own access.

`tests/remote/run.sh user@host` needs something no container can provide: a
machine with an address the visitor can route to. Everything else puts host and
visitor on the same box, so the SSH connection never actually leaves it. Point
it at a disposable host — it installs grantd and edits that machine's sshd,
which is the point.

`tests/remote/digitalocean.sh` does that end to end: provisions a droplet, runs
the suite, and destroys everything on any exit path including failure. About a
cent, about five minutes.

    DIGITALOCEAN_TOKEN=dop_v1_... tests/remote/digitalocean.sh

There is no Cloudflare product that can host this side of the test. Workers do
accept inbound TCP now, but that path runs through Spectrum — and the property
being tested is precisely that Cloudflare is *not* in the path, so a proxied
connection would verify the opposite of the design.

The redeemer needs **OpenSSL 3.x**. macOS ships LibreSSL as `openssl`, which has
no Ed25519 at all; `redeem.sh` looks for a capable binary in the usual places and
says so plainly if there is none. Set `GRANTD_OPENSSL` to override.

## Status

V1: Linux, OpenSSH, one enrolled non-root login account per host, direct SSH
reachability. No relaying, no session recording, no command restrictions, no
Windows.
