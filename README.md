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

## Status

V1: Linux, OpenSSH, one enrolled non-root login account per host, direct SSH
reachability. No relaying, no session recording, no command restrictions, no
Windows.
