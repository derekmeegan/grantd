# grantd: Capability-Based Ephemeral SSH Access for Autonomous Agents

**Version 1.0 — protocol v1 (frozen)**
Source and reference implementations: https://github.com/derekmeegan/grantd

---

## Abstract

Autonomous software agents increasingly need to grant one another access to
machines they control. The established mechanisms — provisioning accounts,
exchanging long-lived public keys, or brokering through a trusted third party —
were designed for human operators working on timescales of days, and each
leaves durable state that outlives the task that motivated it.

We present grantd, a protocol and implementation for issuing short-lived SSH
access as a bearer capability. A host machine runs a local certificate
authority and mints a capability consisting of an identifier and a 32-byte
secret. The secret is transmitted out of band in a URL fragment, which HTTP
clients do not send to servers. A recipient proves possession of that secret by
computing an HMAC over a canonically encoded statement that includes the SSH
public key it wants certified; the host verifies the HMAC and issues a
certificate valid for a bounded window.

The central design property is that the coordination service is an *untrusted
transport*. It never receives a private key, never receives the capability
secret, and cannot produce any value that would authorize access. We state this
as five falsifiable claims (§3.4) and test each against a deliberately
malicious service implementation (§14.2).

We report measurements from a deployed system, including two vulnerabilities
found in external review and the effect of their remediation: a privilege
escalation permitting a visiting agent to mint further capabilities, and the
absence of session termination at certificate expiry. We describe the
remediations and give before-and-after measurements for both (§14.3).

---

## 1. Introduction

The immediate motivation is concrete. An agent operating on a Linux host is
asked to let a second agent — running elsewhere, under a different operator,
possibly in a sandbox with no persistent identity — inspect that host. The
task lasts minutes. The mechanisms available are:

1. **Provision an account and install a public key.** Durable state on both
   sides, and revocation is a manual step that must be remembered.
2. **Share an existing private key.** Confers indefinite authority and cannot
   be scoped or expired.
3. **Broker through a managed service** (§16). Introduces a party that can
   grant access on its own initiative.

Each fails the same test: the authority conferred outlives, and exceeds, the
task. Option 3 additionally relocates trust to an entity whose interests need
not align with the host operator's.

grantd's approach is that the host retains all authority. It runs its own SSH
certificate authority, issues a capability that is a random secret, and signs a
certificate only on presentation of a proof derived from that secret. A
coordination service exists solely so that a host behind NAT can be reached and
woken; it is given no information with which it could act on its own behalf.

### 1.1 Contributions

- A protocol in which the coordination service is provably unable to authorize
  access, specified byte-for-byte so independent implementations agree (§5).
- A two-proof redemption construction separating *authorization* (HMAC under
  the capability secret) from *attribution* (Ed25519 signature under a
  registered agent identity), such that compromise of the attribution layer
  does not confer access (§5.4.4).
- Bidirectional authentication: the host authenticates the visitor by
  certificate, and the visitor authenticates the host by pinning an SSH host
  key carried in the host's own signed record — closing an attack that
  certificate verification alone does not (§6.2).
- A WebSocket transport permitting operation from sandboxes whose only egress
  is HTTP over TLS, without placing the coordination service in the session
  path (§11).
- An empirical evaluation, including adversarial tests against a malicious
  service and measured remediation of two review findings (§14).

---

## 2. Problem statement

Let $H$ be a host machine under an operator's control, and $V$ a visiting agent
requiring shell access to $H$ for a bounded interval. $V$ has no account on
$H$, no pre-shared key, and no prior relationship with $H$'s operator. $H$ may
be behind NAT and may not accept unsolicited inbound connections on arbitrary
ports. $V$ may execute in a sandbox with restricted egress.

We require a mechanism satisfying:

- **R1 — No durable state.** Access expires without an administrative action.
- **R2 — Least authority.** $V$ obtains shell access as one unprivileged
  account and no more; in particular it does not obtain the ability to extend
  its own access or to delegate.
- **R3 — No trusted third party.** Any intermediary required for reachability
  must be unable to grant, extend, or observe access.
- **R4 — No client installation.** $V$ must be able to participate using
  tools already present in a minimal environment.
- **R5 — Mutual authentication.** $H$ must authenticate $V$, and $V$ must
  authenticate $H$. Neither may rely on the intermediary's honesty.

R3 and R5 are the demanding pair. R3 forbids the obvious construction, in which
a broker holds a key and issues credentials. R5 forbids the naive fix, in which
the visitor trusts whatever machine answers the address the broker supplied.

---

## 3. Threat model

### 3.1 Parties

| Party | Holds | Trusted for |
|---|---|---|
| **Host** $H$ | host identity private key, SSH CA private key, capability secrets | All authorization decisions |
| **Coordination service** $S$ | public keys, signed grant metadata, opaque redemption envelopes | Routing and rendezvous only |
| **Visiting agent** $V$ | agent identity private key, ephemeral SSH private key | Nothing; must prove possession of a capability secret |

### 3.2 Adversaries

- **$\mathcal{A}_S$ — Malicious coordination service.** $\mathcal{A}_S$ has
  full control of $S$: its code, storage, and every message it relays. This is
  the primary adversary. It models both a compromised deployment and a
  dishonest operator.
- **$\mathcal{A}_N$ — Network adversary.** Standard Dolev–Yao: reads, drops,
  reorders, and injects messages. Weaker than $\mathcal{A}_S$, which we
  therefore treat as subsuming it for the coordination path.
- **$\mathcal{A}_V$ — Malicious visitor.** A party that legitimately received
  one capability and attempts to exceed it: extend its window, obtain
  additional access, or delegate to a third party. Reviewed externally; see
  §14.3.
- **$\mathcal{A}_R$ — Capability interceptor.** A party that obtains a
  capability URL in transit. Explicitly *not* defended against; the capability
  is a bearer token (§15.1).

### 3.3 Assumptions

1. Ed25519, HMAC-SHA256 and SHA-256 are secure for signatures, MACs and
   collision resistance respectively.
2. The host's private keys are not extracted. Host compromise is total
   compromise and out of scope.
3. The out-of-band channel carrying the capability URL from operator to
   recipient is confidential. §15.1 discusses the consequences when it is not.
4. The host's clock is accurate to within the skew windows of §5.2.
5. OpenSSH correctly enforces certificate validity at authentication. We note
   in §12.2 what this does *not* imply.

### 3.4 Security claims

We state the properties as falsifiable claims. Each is exercised by an
adversarial test (§14.2); the parenthetical names the mechanism.

- **C1 — Fabrication.** $\mathcal{A}_S$ cannot cause $H$ to issue a
  certificate for any key without possessing a capability secret.
  *(HMAC under a secret never transmitted to $S$; §5.4.4.)*
- **C2 — Substitution.** $\mathcal{A}_S$ cannot replace the SSH public key in
  a redemption with one of its own.
  *(`ssh_public_key` is inside the MAC'd statement; §5.4.4.)*
- **C3 — Extension.** $\mathcal{A}_S$ cannot extend a capability's validity.
  *(`expires_at` is inside the host-signed grant, and $H$ re-checks its own
  authoritative copy at signing time; §5.4.3, §7.)*
- **C4 — Principal escalation.** $\mathcal{A}_S$ cannot alter the account a
  certificate authorizes.
  *(The principal is read from $H$'s local enrollment record, never from the
  request; §8.)*
- **C5 — Misdirection.** $\mathcal{A}_S$ cannot cause $V$ to open a session
  with a machine other than $H$.
  *(V pins `ssh_host_public_key` from $H$'s signed registration; §6.2. This is
  the claim that certificate verification alone does not establish.)*

### 3.5 Non-goals

Confidentiality of the capability against a party who obtains it (§15.1);
defence against a compromised host (§3.3.2); restriction of a visitor's actions
*within* the granted account beyond Unix permissions (§15.2); and resistance to
denial of service by $\mathcal{A}_S$, which can always refuse to relay.

---

## 4. Design

### 4.1 Overview

```
   HOST H                     SERVICE S                    VISITOR V
   (CA + secrets)             (router)                     (no prior identity)

   mint capability
   ───────────────────────────────────────────────────────► URL + secret
                                                            (out of band)

                              ◄──── redeem(payload,          compute
                                    agent_sig, proof) ────── HMAC(secret, ·)

   verify proof  ◄──── relay (opaque bytes) ────
   sign certificate ──────────────────────────────────────► certificate

   ◄══════════ direct SSH, host key pinned ═══════════════
```

$S$ is on the control path and never on the session path.

### 4.2 Capability transmission

A capability URL is:

```
https://<origin>/g/<host_id>/<grant_id>#<secret_text>
```

The secret occupies the URL **fragment**. Per RFC 3986 §3.5, the fragment is
dereferenced client-side and is not transmitted in the request. $S$ therefore
receives `<host_id>` and `<grant_id>` — which it needs for routing — and cannot
receive the secret even from a client that naively pastes the whole URL into a
`GET`. The property is structural rather than procedural: it does not depend on
client discipline.

### 4.3 Two independent proofs

A redemption carries two cryptographic values over the same statement $P$:

$$
\begin{aligned}
\sigma &= \mathrm{Ed25519\text{-}Sign}(sk_V,\; \mathrm{CBE}(\texttt{CTX\_REDEMPTION\_SIG}, P)) \\
\tau   &= \mathrm{HMAC\text{-}SHA256}(k_{\text{grant}},\; \mathrm{CBE}(\texttt{CTX\_REDEMPTION\_MAC}, P))
\end{aligned}
$$

$\tau$ authorizes; $\sigma$ attributes. The separation is deliberate: $\sigma$
binds the redemption to a registered identity for audit and rate limiting, and
its forgery confers nothing, because issuance is gated on $\tau$ alone. The two
contexts differ so that the signature and the MAC are distinct objects over the
same statement and neither can be replayed as the other.

### 4.4 Self-certifying identifiers

$\texttt{host\_id} = \texttt{"h\_"} \parallel b32(\mathrm{SHA\text{-}256}(pk_H)[0{:}20])$,
and correspondingly for agents. Any party holding the public key verifies that
the claimed identifier equals the derived one before trusting the message.
There is no registry to consult and no name to be mis-assigned: an identifier
is a commitment to a key.

This is what makes C5 tractable. Because `host_id` is a hash of $H$'s key, a
visitor holding a capability URL already knows which key must have signed the
record it fetches, before it trusts any field in that record.

### 4.5 Bidirectional authentication

$H$ authenticates $V$ by the certificate its own CA issued. $V$ authenticates
$H$ by pinning `ssh_host_public_key`, taken from $H$'s signed registration and
keyed in `known_hosts` by `host_id` rather than by address.

The asymmetry is worth stating plainly, because it is the subtle half. A
certificate proves that *the visitor's key was signed by the host's CA*. It
says nothing about *which machine answered the address*. If $S$ resolves the
address — which it does when the host is named under a DNS suffix $S$ manages
(§11.3) — then a signature over the *name* is worth nothing to the party doing
the resolving. Only a key $S$ cannot produce closes that gap.

---

## 5. Protocol specification (normative)

Implementations MUST conform to this section. The fixtures in
`protocol/test-vectors/` are normative and are regenerated from, and verified
against, both reference implementations.

### 5.1 Canonical Binary Encoding

All signed and MAC'd bytes are produced by Canonical Binary Encoding (CBE).
CBE is used in preference to canonical JSON to eliminate canonicalization
ambiguity — key ordering, duplicate keys, Unicode escaping, number formatting,
insignificant whitespace — as a class rather than case by case.

**Primitives.**

```
u32be(n)  := 4-byte big-endian unsigned integer
u64be(n)  := 8-byte big-endian unsigned integer
LP(b)     := u32be(len(b)) || b
```

**Value types.**

| Tag | Name | Encoding |
|---|---|---|
| `0x01` | STRING | UTF-8. MUST be valid UTF-8; MUST NOT contain U+0000 |
| `0x02` | U64 | `u64be(v)`, exactly 8 bytes |
| `0x03` | BYTES | raw octets |
| `0x04` | BOOL | one byte, `0x00` or `0x01` |

There is no null, no floating point, and no nested container. Every message is
a flat, ordered list of typed fields.

**Message encoding.**

```
CBE(context, fields) :=
      LP(utf8(context))
   || u32be(count(fields))
   || for each field i, in schema-declared order:
          LP(utf8(name_i)) || tag_i || LP(value_bytes_i)
```

Rules:

- Field order is the order declared in §5.4 — never sorted, never the order of
  appearance in a JSON envelope.
- Field *names* are encoded, so no field can be shifted into another's
  position.
- `count(fields)` is exact. Every declared field is always present; v1 has no
  optional signed fields.
- `context` is a domain separation string. Two distinct message types can never
  produce identical canonical bytes.
- Implementations MUST reject a STRING that is not valid UTF-8, and MUST reject
  a U64 exceeding $2^{63}-1$, so that languages with signed 64-bit integers
  cannot disagree.

**Domain separation strings.**

| Constant | Value |
|---|---|
| `CTX_HOST_REGISTER` | `grantd/v1/host-register` |
| `CTX_HOST_CONNECT` | `grantd/v1/host-connect` |
| `CTX_GRANT` | `grantd/v1/grant` |
| `CTX_REDEMPTION_SIG` | `grantd/v1/redemption-agent-sig` |
| `CTX_REDEMPTION_MAC` | `grantd/v1/redemption-proof` |
| `CTX_AGENT_REGISTER` | `grantd/v1/agent-register` |

### 5.2 Time

All protocol timestamps are integer seconds since the Unix epoch, UTC, encoded
as CBE `U64` and as JSON numbers. RFC 3339 strings are never signed; where they
appear in unsigned envelopes under an `_rfc3339` suffix they MUST be ignored by
verifiers.

Accepted skew: ±300 s for host registration, host connect, and agent
registration; ±120 s for redemption payloads. A verifier MUST reject an
out-of-window timestamp before performing any further work that depends on it.

### 5.3 Keys and identifiers

**Key types.** All protocol identity keys are Ed25519; raw public keys are 32
bytes. The SSH CA is also Ed25519 but is a *separate* key used only to sign SSH
certificates. The host identity key is used only for CBE signatures. Neither is
ever used for the other's purpose.

**Identifier derivation.**

```
id_material(pk) := SHA-256(pk_raw_32)
b32(b)          := RFC 4648 base32, lowercase "abcdefghijklmnopqrstuvwxyz234567", unpadded
host_id         := "h_" || b32(id_material(pk_host)[0:20])
agent_id        := "a_" || b32(id_material(pk_agent)[0:20])
```

Base32 of 20 bytes is exactly 32 characters, so identifiers match
`^[ha]_[a-z2-7]{32}$`. Identifiers are self-certifying (§4.4): a party holding
the public key MUST verify the claimed identifier equals the derived one before
trusting anything else in the message.

**Capability identifiers and secrets.**

```
grant_id     := "g_" || b32(random 10 bytes)         matches ^g_[a-z2-7]{16}$
grant_secret := 32 bytes from a CSPRNG
secret_text  := base64url(grant_secret), unpadded    matches ^[A-Za-z0-9_-]{43}$
```

The capability secret is the only bearer authority in the system. It is created
on the host, stored on the host, and transmitted out of band. It MUST NOT be
sent to, logged by, or derivable by the coordination service.

**SSH public key encoding.** Carried as a one-line `authorized_keys` entry of
exactly two whitespace-separated fields and no comment. v1 accepts only
`ssh-ed25519`; the blob MUST be ≤ 1024 bytes. A comment, trailing whitespace,
options prefix, or additional field is a rejection rather than something to
normalize — the exact bytes are what is signed. Fingerprints are OpenSSH's
`SHA256:` || base64(SHA-256(blob)), unpadded.

### 5.4 Message schemas

#### 5.4.1 Host registration — `CTX_HOST_REGISTER`

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `version` | U64 | `1` |
| 2 | `host_id` | STRING | must equal derived id |
| 3 | `identity_public_key` | BYTES | 32 raw bytes |
| 4 | `ssh_ca_public_key` | STRING | authorized_keys format |
| 5 | `ssh_host_public_key` | STRING | authorized_keys format; the key $V$ pins |
| 6 | `hostname` | STRING | DNS name or address $V$ will reach |
| 7 | `ssh_port` | U64 | 1..65535 |
| 8 | `ssh_user` | STRING | enrolled login account |
| 9 | `timestamp` | U64 | unix seconds |
| 10 | `nonce` | BYTES | 16 random bytes |

Signed with the host identity key. Registration is idempotent per `host_id`:
re-registration updates fields 4–8 provided the signature verifies under the
*already registered* identity key. The identity key is immutable, since it
defines the identifier.

Fields 4 and 5 point in opposite directions and are never the same key. Field 4
is how $H$ authenticates $V$ (sshd trusts certificates under it); field 5 is
how $V$ authenticates $H$. A host MUST NOT publish an empty field 5, and a
verifier MUST reject a record lacking it.

#### 5.4.2 Host connect — `CTX_HOST_CONNECT`

| # | Field | Type |
|---|---|---|
| 1 | `version` | U64 |
| 2 | `host_id` | STRING |
| 3 | `path` | STRING |
| 4 | `timestamp` | U64 |
| 5 | `nonce` | BYTES (16) |

Transmitted as `X-Grantd-Timestamp`, `X-Grantd-Nonce`, `X-Grantd-Signature`
headers on the WebSocket upgrade. `path` is reconstructed by the verifier and
not read from the request, so a signature for one endpoint cannot verify
against another. Nonces seen within the skew window are rejected.

#### 5.4.3 Grant metadata — `CTX_GRANT`

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `version` | U64 | `1` |
| 2 | `host_id` | STRING | |
| 3 | `grant_id` | STRING | |
| 4 | `ssh_user` | STRING | principal the certificate will carry |
| 5 | `created_at` | U64 | |
| 6 | `expires_at` | U64 | `> created_at`; `expires_at - created_at ≤ 28800` |

Signed with the host identity key. This is the *only* capability information
$S$ receives. It contains no secret and no derivative of one. Because
`expires_at` is inside the signature and $H$ re-checks its own copy at signing
time, C3 holds.

#### 5.4.4 Redemption payload — `CTX_REDEMPTION_SIG`, `CTX_REDEMPTION_MAC`

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `version` | U64 | `1` |
| 2 | `host_id` | STRING | |
| 3 | `grant_id` | STRING | |
| 4 | `agent_id` | STRING | must equal id derived from field 5 |
| 5 | `agent_public_key` | BYTES | 32 raw bytes |
| 6 | `ssh_public_key` | STRING | the key to be certified |
| 7 | `timestamp` | U64 | |
| 8 | `nonce` | BYTES (16) | |

Both proofs of §4.3 are computed over this field list. Field 6 is inside the
MAC'd statement, which is precisely why C2 holds: substituting an SSH key
requires forging an HMAC under a secret the substituting party has never seen.

#### 5.4.5 Agent registration — `CTX_AGENT_REGISTER`

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `version` | U64 | `1` |
| 2 | `agent_id` | STRING | must equal derived id |
| 3 | `public_key` | BYTES | 32 raw bytes |
| 4 | `challenge_id` | STRING | from `POST /v1/agent-challenges` |
| 5 | `pow_nonce` | STRING | verbatim ASCII, ≤ 64 bytes |
| 6 | `timestamp` | U64 | |

### 5.5 JSON envelopes

Binary values are base64url without padding. The JSON envelope is a transport
container only: verification always re-derives canonical bytes from parsed
fields via CBE, and a verifier MUST NOT sign or verify raw JSON text. Unknown
keys MUST be ignored and cannot influence canonical bytes, since CBE encodes
only declared fields.

### 5.6 Capability URL

As §4.2. `GET /g/<host_id>/<grant_id>` returns plain-text redemption
instructions and MUST NOT echo, log, or accept a secret in any request
position.

---

## 6. Validation

### 6.1 Host-side redemption validation

$H$ is the sole authority. On redemption it performs, in order:

1. Parse envelope; enforce size limits.
2. `version == 1`.
3. `host_id` equals this host's identifier.
4. `|now − timestamp| ≤ 120`.
5. `nonce` is 16 bytes and unseen within the skew window.
6. `agent_id` equals the identifier derived from `agent_public_key`.
7. `agent_signature` verifies over `CBE(CTX_REDEMPTION_SIG, P)`.
8. `ssh_public_key` parses as a valid `ssh-ed25519` entry.
9. The capability exists locally.
10. It is not revoked, not expired, and not redeemed.
11. `proof` equals `HMAC-SHA256(secret, CBE(CTX_REDEMPTION_MAC, P))`, compared
    in constant time.
12. Atomically mark redeemed (§7).
13. Sign the certificate.

Steps 1–8 are cheap and precede any database write, so an unauthenticated flood
cannot consume capabilities. Step 11 occurs *after* the atomic claim so that a
wrong MAC cannot burn a capability: the claim is rolled back on failure (§7).

### 6.2 Visitor-side validation

The redemption response is unsigned and $S$ is untrusted; $V$ MUST NOT connect
on the strength of the response alone. Before redeeming, and again before
connecting, $V$:

1. Fetches `GET /v1/hosts/<host_id>` and reads `registration` and `signature`.
2. Checks `registration.host_id` equals the capability's `host_id`, and that
   both equal the identifier derived from `registration.identity_public_key`.
3. Verifies `signature` over `CBE(CTX_HOST_REGISTER, registration)` under that
   key.
4. Takes `hostname`, `ssh_port`, `ssh_user`, `ssh_ca_public_key` and
   `ssh_host_public_key` from the verified registration. The corresponding
   fields in the redemption response MUST match, or $V$ rejects the response.
5. Checks the certificate is a *user* certificate, signed by
   `ssh_ca_public_key`, over $V$'s own key, with exactly one principal equal to
   `ssh_user`, inside its validity window.
6. Pins `ssh_host_public_key`: a `known_hosts` entry keyed by `host_id`, with
   `HostKeyAlias=<host_id>`, `StrictHostKeyChecking=yes`,
   `HostKeyAlgorithms=ssh-ed25519`.

Steps 5 and 6 answer different questions, and conflating them is the error this
design exists to prevent (§4.5). Keying the pin by `host_id` also makes it
independent of how the address is spelled and of which transport carries the
session (§11).

A visitor that interpolates `hostname` or `ssh_user` into a command line MUST
validate them against §5.4.1 and MUST pass them as separate arguments
(`-l user`, `-p port`, `-- host`), never as `user@host`.

---

## 7. Single-use semantics

A capability authorizes exactly one $(\texttt{agent\_id},
\texttt{ssh\_public\_key})$ pair. The claim and MAC verification occur within
one `BEGIN IMMEDIATE` transaction:

```sql
BEGIN IMMEDIATE;
  SELECT secret, expires_at, revoked_at, redeemed_at, redeemed_agent_id, redeemed_key_fp
    FROM grants WHERE id = ?;
  -- absent / revoked / expired          -> ROLLBACK, reject
  -- redeemed by a different agent/key   -> ROLLBACK, GRANT_ALREADY_REDEEMED
  -- MAC mismatch                        -> ROLLBACK, BAD_PROOF  (not consumed)
  UPDATE grants
     SET redeemed_at = ?, redeemed_agent_id = ?, redeemed_key_fp = ?
   WHERE id = ? AND redeemed_at IS NULL;
COMMIT;
```

Because SQLite serializes write transactions, $N$ concurrent redemptions with
$N$ distinct keys yield exactly one winner; the remainder receive
`GRANT_ALREADY_REDEEMED`. Measured at $N = 200$ in §14.1.

**No retry path.** A capability is consumed once, with no exception for the
agent that won it; resubmitting an identical envelope is rejected as a replayed
nonce. An earlier design re-issued the stored certificate when the same agent
presented the same key, so that a lost response was recoverable. It was removed
before release: it was the subtlest code in the signer, it entangled replay
detection with the claim transaction, and capabilities are free to mint. A lost
response now costs one more capability rather than a special case inside the
one function where an error means two keys obtain access.

**Expiry is local.** $S$'s copy of `expires_at` is a routing optimization. $H$'s
copy is authoritative and is re-checked at signing time.

---

## 8. Certificate issuance

| Field | Value |
|---|---|
| type | `ssh-ed25519-cert-v01@openssh.com`, **user** certificate |
| key | the visitor's `ssh_public_key` |
| serial | random non-zero `uint64`, unique per capability |
| key id | `grantd:<grant_id>:<agent_id>` |
| valid principals | exactly one: the enrolled `ssh_user` |
| valid after | `now − 30` |
| valid before | `grant.expires_at` |
| critical options | none |
| extensions | `permit-pty`, `permit-user-rc` |

Deliberately withheld: `permit-port-forwarding`, `permit-agent-forwarding`,
`permit-X11-forwarding`. A visiting agent receives an interactive shell, not a
tunnel into the operator's network.

The principal can never be chosen by the redeemer. It is fixed at enrollment
and copied from $H$'s own configuration; `root` enrollment is refused. Host
trust is configured by `TrustedUserCAKeys /etc/grantd/ssh_ca.pub`. This is the
mechanism behind C4.

The `key id` is not decorative: it is what associates a live session with the
capability that authorized it, and §12.2 depends on it.

---

## 9. Service interface

### 9.1 Error codes

| Code | HTTP | Meaning |
|---|---|---|
| `BAD_REQUEST` | 400 | malformed body, bad base64, size limit |
| `UNSUPPORTED_VERSION` | 400 | `version ≠ 1` |
| `ID_MISMATCH` | 400 | claimed identifier ≠ derived identifier |
| `BAD_SIGNATURE` | 401 | Ed25519 verification failed |
| `STALE_TIMESTAMP` | 401 | outside skew window |
| `REPLAYED_NONCE` | 401 | nonce previously seen |
| `HOST_NOT_FOUND` | 404 | unknown `host_id` |
| `GRANT_NOT_FOUND` | 404 | unknown `grant_id` |
| `AGENT_NOT_FOUND` | 404 | unregistered `agent_id` |
| `CHALLENGE_NOT_FOUND` | 404 | unknown or expired challenge |
| `CHALLENGE_CONSUMED` | 409 | challenge already used |
| `BAD_ANSWER` | 401 | proof of work incorrect |
| `HOST_OFFLINE` | 503 | no rendezvous connection |
| `HOST_TIMEOUT` | 504 | host did not answer in time |
| `GRANT_EXPIRED` | 410 | expired at the authoritative signer |
| `GRANT_REVOKED` | 410 | revoked at the signer |
| `GRANT_ALREADY_REDEEMED` | 409 | consumed by a different key |
| `BAD_PROOF` | 401 | HMAC failed; capability not consumed |
| `RATE_LIMITED` | 429 | abuse control |
| `TOO_MANY_GRANTS` | 429 | host active-capability cap |

### 9.2 Endpoints

```
GET    /                                             protocol description
GET    /health
GET    /whitepaper                                   this document

POST   /v1/agent-challenges                          begin agent registration
POST   /v1/agents                                    register agent identity
GET    /v1/agents/:agent_id                          public agent record

PUT    /v1/hosts/:host_id                            register / update host
GET    /v1/hosts/:host_id                            public host record
GET    /v1/hosts/:host_id/connect                    WebSocket rendezvous
PUT    /v1/hosts/:host_id/grants/:grant_id           publish signed metadata
GET    /v1/hosts/:host_id/grants/:grant_id           public metadata
POST   /v1/hosts/:host_id/grants/:grant_id/redeem    redeem capability

GET    /g/:host_id/:grant_id                         redemption instructions
GET    /install                                      installer
GET    /redeem.sh, /redeem.mjs, /bridge-proxy.py     reference clients
```

### 9.3 Rendezvous frames

WebSocket, JSON, strictly versioned. The complete message vocabulary:

```
S → H : {"t":"redeem.request","id":"<req>","body_b64":"<base64url of envelope>"}
H → S : {"t":"redeem.response","id":"<req>","status":200,"body_b64":"<base64url>"}
S → H : {"t":"ping","id":"<req>"}
H → S : {"t":"pong","id":"<req>"}
S → H : {"t":"hello","protocol_version":1}
```

Payloads travel as base64url of exact bytes, never as nested JSON. This is not
a serialization preference but a property the design depends on. First, the
request body is what $H$ verifies; were $S$ to parse and re-serialize it, $H$
would be verifying bytes $S$ produced rather than bytes $V$ signed. Second, a
JSON round trip through a runtime whose only numeric type is IEEE-754 double
silently corrupts 64-bit values — including the certificate serial. Opaque
bytes make both failures structurally impossible rather than merely unlikely.

There is no generic RPC frame, and there will never be a frame carrying a
command, a path, a filename, or a shell string. Unknown `t` values are dropped
and counted.

### 9.4 Response encoding note

The certificate `serial` is a decimal **string**, not a JSON number. It is a
random `uint64`, and such a value does not survive a parser backed by `float64`
— which is most of them, including every browser and the coordination service
itself. It is an identifier, not an arithmetic quantity.

---

## 10. Admission control

Agent registration is *required to redeem* and is *not a security boundary*.
Both halves matter.

It is required: $S$ rejects a redemption from an unregistered `agent_id` with
`AGENT_NOT_FOUND` before forwarding anything, so reaching a host at all costs a
proof of work.

It cannot be a boundary, structurally. $H$ is the only party whose opinion
authorizes access, and it has no network and no registry to consult; it
therefore cannot check registration, and $\mathcal{A}_S$ could skip the check
entirely. Nothing in §3.4 rests on it. Authority comes only from possession of
a capability secret.

`POST /v1/agent-challenges` returns a proof-of-work prefix and a difficulty in
bits. The client finds `pow_nonce` such that
$\mathrm{SHA\text{-}256}(\texttt{prefix} \parallel \texttt{utf8(nonce)})$ has at
least that many leading zero bits. At 20 bits this is roughly one second of
CPU: negligible for one agent, expensive for a million. Its purpose is to
prevent unauthenticated callers allocating storage without bound — it protects
the operator's bill, not the host machine. Challenges are single-use, expire in
ten minutes, and are consumed atomically so one solved proof cannot mint two
registrations.

An earlier draft additionally posed a natural-language question, on the theory
that it demonstrated liveness and instruction-following. It was removed before
release: the reference solver shipped in the same repository and answered every
template, nothing consumed the signal, and it cost a round trip to produce a
value nobody read. A check that reads as security to a casual reviewer while
providing none is worse than no check.

---

## 11. Transport under constrained egress

### 11.1 The constraint

Agent sandboxes increasingly permit only HTTP over TLS. Such an environment
cannot open a raw TCP connection to port 22. It frequently cannot open one to
port 443 either: the egress gateway inspects the first bytes of a tunnel and
resets anything that is not a TLS `ClientHello`. Relocating sshd to 443 does
not help, because the obstacle is protocol inspection, not port filtering.

### 11.2 The bridge

$H$ may optionally serve sessions over a WebSocket on 443: nginx terminates
TLS, and a small binary copies bytes between the WebSocket and `127.0.0.1:22`.
The visitor uses it as an SSH `ProxyCommand`. To the gateway the session is
ordinary HTTPS.

The security argument is unchanged, and the reason is §4.5. TLS terminates on
$H$, so $S$ remains absent from the session path. $V$ still pins
`ssh_host_public_key`, and because the pin is keyed by `host_id` rather than by
address, it is identical across transports. The protocol requires no change
whatsoever; only the pipe differs.

The bridge's destination is compiled in and cannot be influenced by any flag,
header, query or path. A process reachable from a reverse proxy that permitted
its caller to name a destination would be an open relay on the loopback
interface.

One operational consequence must be stated: sshd observes every bridged session
as originating from `127.0.0.1`. Source-address controls — `fail2ban`,
per-source connection limits — cannot distinguish bridged visitors. The reverse
proxy's connection and rate limits replace them.

### 11.3 Host naming

Where the operator enrolls with a DNS suffix, $S$ publishes one address record
per host under it. The record name is *derived from `host_id`* and never read
from the registration, so an enrolled host can only affect its own label; and a
record is written only when the host's *signed* hostname already equals that
derived name. Records are never proxied, so the SSH path remains direct.

This grants $S$ a DNS credential, which is the only capability it holds
reaching outside itself. The bound on its misuse is exactly C5: $S$ can
misdirect a visitor to the wrong address, and the visitor's host-key pin
converts that into a refused connection rather than a session with a stranger.

---

## 12. Bounding visitor authority

Both mechanisms in this section were added in response to external review
(§14.3) and correct cases where the implementation conferred more than the
design intended.

### 12.1 Separation of minting from receiving

The capability-minting interface is a Unix socket guarded by the peer
credentials the kernel reports (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on
macOS), which no userspace process can forge. The guard is sound; what matters
is which uid it admits.

If that uid is the account visitors log into, a visitor inherits the ability to
mint capabilities: it can extend its own access beyond the interval it was
given, and can delegate to third parties. Requirement R2 fails, and "keep
lifetimes short" ceases to be a mitigation, because the guest chooses the
lifetime.

The minting account MUST therefore differ from the enrolled login account. The
reference installer refuses to proceed otherwise, and verifies the property
empirically before reporting success by attempting to mint as the visiting
account and aborting if that succeeds.

### 12.2 Session termination at expiry

OpenSSH evaluates certificate validity at *authentication*. Expiry therefore
prevents new connections and does not affect a session already established. A
session opened one second before expiry runs indefinitely.

This is OpenSSH behaving as documented, not a defect in it; but it means an
unaugmented deployment does not enforce what a stated interval is universally
read as promising. A reaper closes the gap: periodically it obtains the set of
concluded capabilities from the signer, matches them against the certificate
`key_id` values sshd recorded at authentication (§8), and signals the
corresponding sessions.

It signals only processes sshd recorded as presenting a grantd certificate, and
re-validates process identity before doing so, so neither a recycled pid nor an
operator's own session is in scope. Revocation, previously affecting only
future redemptions, now also terminates a running session.

The mechanism is polling, so termination is bounded by the poll interval rather
than instantaneous (§15.3).

---

## 13. Operational failure semantics

| Situation | Behavior |
|---|---|
| Coordination service unavailable | Existing certificates continue to work; no new redemptions |
| Host daemon offline | Capability remains valid until expiry; redeemer receives `HOST_OFFLINE` |
| Host reboots | Signer state persists; daemon reconnects; unexpired capabilities remain redeemable |
| Redemption response lost | Capability is spent; mint another (§7) |
| Capability expires in flight | Signer is authoritative; `GRANT_EXPIRED` |
| Coordination storage loss | No effect on host security; metadata may need republishing |
| Host key rotated on the machine | Re-enroll; until then visitors pin the old key and refuse. Failing closed is intended |

---

## 14. Evaluation

### 14.1 Concurrency

The single-use property of §7 is exercised by 200 simultaneous redemptions of
one capability, each presenting a distinct SSH key. Exactly one succeeds; the
remaining 199 receive `GRANT_ALREADY_REDEEMED`. The result follows from
SQLite's serialization of write transactions and holds independently of
arrival order.

### 14.2 Adversarial testing against a malicious service

Claims C1–C5 are tested against a coordination service implementation that
actively attempts each attack, rather than against a mock that declines to.
The suite asserts that the malicious service cannot fabricate a capability,
extend an expiry, substitute an SSH public key, alter the certificate
principal, cause a second certificate to be issued, or induce the visitor to
connect to a substituted machine.

### 14.3 Review findings and remediation

An external reviewer examined the implementation and reported two respects in
which it conferred more than §3.4 claims. Both were confirmed by direct
measurement on a deployed host, remediated, and re-measured.

**Finding 1 — visitor could mint capabilities.** The installer assigned the
minting socket's uid to the enrolled login account (§12.1). From a session
opened under a 30-minute capability, a visitor minted an 8-hour one and
received a full capability URL, permitting both self-extension and delegation.

| | Before | After |
|---|---|---|
| Visitor mints capability | succeeds (8 h issued) | connection refused (`curl` exit 7) |

**Finding 2 — sessions outlived expiry.** A session established under a
certificate expiring at $t$ continued past $t$.

| | Before | After |
|---|---|---|
| Session at $t + 94\,\mathrm{s}$ | alive | terminated within the same second as expiry |
| New connection with expired cert | refused | refused (unchanged) |

The second row is worth noting: expiry *was* correctly refusing new
authentications before the fix. The gap was confined to established sessions,
which is precisely why review found it and routine use would not.

We report these findings because their character is instructive. Neither lay in
the cryptographic core, which the reviewer examined and did not fault. Finding
1 was a configuration defect in an installer — a sound mechanism aimed at the
wrong principal. Finding 2 was an incorrect assumption about a dependency's
semantics. In a system whose security argument is concentrated in its protocol,
these are the residual places for defects to live.

### 14.4 Cross-implementation agreement

Two independent implementations — Go (host signer, daemon, bridge) and
TypeScript (coordination service) — are verified against shared normative
fixtures. Derivations duplicated across languages, such as the host naming rule
of §11.3, are separately tested in both, since a divergence would manifest not
as an error but as a host silently never receiving a name.

---

## 15. Limitations

### 15.1 The capability is a bearer token

Anyone who obtains a capability URL before it is redeemed can redeem it. There
is no recipient binding: the design deliberately requires no prior identity
from the visitor (R4), and these are in tension. The mitigations are short
lifetimes, single use, and the fragment placement of §4.2, which prevents
inadvertent transmission to $S$ but not deliberate disclosure by a holder.

Recipient binding — encrypting the capability to a visitor public key — is
compatible with this protocol and is not implemented in v1.

### 15.2 No intra-session restriction

A visitor can do whatever the enrolled account can do. There are no command
restrictions and no session recording. The bound is the account and the
interval. If that account has `sudo`, the visitor has `sudo`; `root` enrollment
is refused, but no further scoping is attempted.

### 15.3 Termination is polled

Session termination (§12.2) runs on an interval, so a session may outlive its
expiry by up to that interval. Eliminating the window requires an sshd-side
mechanism rather than external polling.

### 15.4 Revocation is not distributed

There is no certificate revocation list. Revoking a capability prevents further
redemption and terminates running sessions, but an already-issued certificate
remains cryptographically valid until expiry. Short lifetimes are the design
response, not an omission awaiting correction.

### 15.5 Availability

$\mathcal{A}_S$ can deny service by refusing to relay. No claim in §3.4
addresses availability, and none can: a party required for reachability can
always decline to provide it.

---

## 16. Related work

**SSH certificate authorities.** OpenSSH has supported user certificates since
5.4 [1]. grantd's contribution is not the certificate but the issuance path:
the CA is per-host rather than organizational, and issuance is gated on a
bearer capability rather than on directory membership.

**Managed access brokers.** Teleport, Boundary and Tailscale SSH interpose a
control plane that can issue credentials on its own authority. This is
appropriate where the operator and the broker are the same organization; it
violates R3 where they are not. grantd's coordination service is deliberately
incapable of issuance, which is a weaker service and a stronger guarantee.

**Capability tokens.** Macaroons [2] and Biscuit provide attenuable, offline-
verifiable capabilities with caveats. grantd's capability is deliberately
simpler — an opaque secret with no structure — because attenuation is expressed
in the SSH certificate, which the operating system already enforces, rather
than in a token whose caveats every consumer must interpret correctly.

**Out-of-band secret placement.** Using the URL fragment to keep a secret from
the server is established practice in client-side encryption tools. Its
application here is to guarantee that a routing intermediary cannot learn a
capability even when handed the whole URL.

**Protocol specification style.** The approach of specifying canonical bytes
and domain separation precisely enough for independent implementations to
agree, and of publishing rationale alongside the construction, follows the
WireGuard paper [3].

---

## 17. Conclusion

grantd demonstrates that ephemeral, mutually authenticated machine access can
be delivered without a trusted third party, without durable state on either
side, and without a client installation. The essential move is to give the
coordination service exactly the information it needs to route — two
identifiers and a host-signed record containing no secrets — and nothing with
which it could act.

The experience reported in §14.3 suggests where attention is best directed once
a protocol's core is settled. The cryptographic construction survived review
unchanged. Both defects lay at its edges: an installer aiming a sound mechanism
at the wrong principal, and an assumption about when a dependency enforces a
deadline. Systems of this shape do not usually fail at the cryptography, and
review effort proportioned to that observation will find more.

---

## Appendix A — Values that are never logged

The capability secret, its textual encoding, any complete capability URL, any
URL fragment, any private key, the `proof` value, and SSH session content.
Logs carry `host_id`, `agent_id`, `grant_id`, certificate serial, and SSH key
SHA-256 fingerprints only.

## Appendix B — Normative fixtures

`protocol/test-vectors/v1.json` contains canonical byte sequences, derived
identifiers, signatures and MACs for every message type in §5.4. It is
normative: an implementation that disagrees with a fixture is incorrect,
regardless of whether it interoperates with the reference implementations.

## Appendix C — Protocol status

Protocol v1 is **frozen**. Any change to canonical bytes, domain separation
strings, identifier derivation, or certificate fields constitutes a new
protocol version rather than an amendment to this document.

Three pre-release amendments were made before any external consumer existed.
The `answer` field was removed from agent registration when the
natural-language challenge was dropped (§10). The public host record gained the
host's signed registration so a visitor could verify it (§6.2). The
`ssh_host_public_key` field was added to host registration (§5.4.1) so a
visitor could pin the machine it reaches — a signed hostname being worth
nothing to whoever resolves the name, while the host key is what the resolver
cannot produce. The first two changed no canonical bytes; the third did, and is
why this notice exists rather than a version increment. Fixtures were
regenerated and both implementations re-verified.

---

## References

[1] OpenSSH. *PROTOCOL.certkeys*. https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys

[2] A. Birgisson, J. G. Politz, Ú. Erlingsson, A. Taly, M. Vrable, M. Lentczner.
*Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in
the Cloud.* NDSS, 2014.

[3] J. A. Donenfeld. *WireGuard: Next Generation Kernel Network Tunnel.* NDSS,
2017.

[4] T. Berners-Lee, R. Fielding, L. Masinter. *Uniform Resource Identifier
(URI): Generic Syntax.* RFC 3986, 2005. §3.5.

[5] S. Josefsson. *The Base16, Base32, and Base64 Data Encodings.* RFC 4648,
2006.

[6] S. Josefsson, I. Liusvaara. *Edwards-Curve Digital Signature Algorithm
(EdDSA).* RFC 8032, 2017.

[7] H. Krawczyk, M. Bellare, R. Canetti. *HMAC: Keyed-Hashing for Message
Authentication.* RFC 2104, 1997.

[8] I. Fette, A. Melnikov. *The WebSocket Protocol.* RFC 6455, 2011.
