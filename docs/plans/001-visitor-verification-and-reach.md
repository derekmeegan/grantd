# Plan 001 — Visitor-side verification, then reach

Status: ready to execute. Branch: `claude/code-session-review-fdav8n`.

This document is written for an agent that has **no prior context**. Every
claim below was verified against the code at commit `e25a0d4` and against live
measurements from inside a Claude Code managed sandbox on 2026-09-03. File
references are `path:line` at that commit. Decisions marked **DECIDED** have
been made by the project owner and are not to be relitigated; execute them.
Items marked **DECISION NEEDED** must be raised before that step is built.

Read in this order before touching anything:
`README.md`, `protocol/v1.md`, `install/redeem.sh`, `go/internal/protocol/messages.go`,
`cloudflare/src/protocol.ts`, `cloudflare/src/durable-objects/host.ts`,
`go/signer/signer.go`, `go/cmd/grant-signer/main.go`, `tests/e2e/run.sh`.

---

## 0. Why this plan exists

grantd's security model (README "Security model", invariants 1–7) protects the
**host** from a compromised coordination service. It says nothing about
protecting the **visitor** from that service, and today nothing does:

| Fact | Where |
|---|---|
| The shipped `ssh` command carries no host-key options. Non-interactively (no controlling tty) OpenSSH cannot prompt and exits `Host key verification failed`. | `install/redeem.sh:394-403`, `cloudflare/src/routes/docs.ts:145-146` |
| Every test that logs in as a visitor uses `StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`. The only exercised path disables host verification. | `tests/e2e/run.sh:136-139`, `tests/remote/run.sh:191-192`, `tests/vm/run.sh:130-131`, `tests/install/run.sh:169-170`, `.github/workflows/ci.yml:158-160` |
| The redemption response (`hostname`, `port`, `user`, `certificate`) is unsigned. `redeem.sh` takes its connection target from it. | `protocol/v1.md` §10 "Redemption response"; `install/redeem.sh:377-381` |
| The host record is served **unsigned**. `HostDO.register()` verifies the signature and discards it; the `host` table has no signature column; `publicRecord()` returns bare fields. Grants, by contrast, are served signed (`grantRecord()` returns `signed_payload` + `host_signature`). | `cloudflare/src/durable-objects/host.ts:84-95, 173-212, 219-234, 366-377` |
| No SSH **host** key exists anywhere in the protocol. The only fingerprint code is for the agent's ephemeral key. | `grep -rn fingerprint go/` |

Consequence: the coordination service can send any visitor to a machine it
controls, undetectably, without touching DNS. The visitor authenticates *to*
that machine with a certificate the real host issued (or a fake one — the
attacker's sshd accepts whatever it likes), gets a shell, and proceeds to type,
upload, and read shell output as if it were the customer's box. For an agent
that is an attacker-controlled input channel.

The anchor to fix it already exists: `host_id = "h_" + b32(sha256(identity_pk)[0:20])`
(`protocol/v1.md` §3.2) rides in the capability URL, which arrives out of band.
Chain: capability URL → `host_id` → identity key (check hash) → signed host
record (check signature) → `hostname`/`ssh_port`/`ssh_user`/**`ssh_host_public_key`**.
Every link is service-unforgeable. The service keeps the ability to misroute
(deny service) and loses the ability to impersonate.

Everything downstream (a public DNS name per host, a 443 bridge) *widens* this
gap if it lands first, because it hands the service DNS control and a valid TLS
cert for every host name. So Phase 1 is a prerequisite for Phases 2 and 3 and
is worth shipping on its own.

### Measured facts about the target environment (Claude Code sandbox)

These justify Phases 2–3 and constrain their design. Re-measure if in doubt.

| Question | Result |
|---|---|
| Egress TCP ports | Only 80 and 443. 22, 2222, 8080, 8443 blocked. A different sshd port does not help. |
| Domain allowlist | None in this environment. (Other operators, e.g. Poke, do allowlist — the domain still matters for them.) |
| TLS on 443 | Intercepted on both paths. Direct path: `Egress Gateway SDS Issuing CA` (Envoy). `HTTPS_PROXY` CONNECT path: `CCR Upstream Proxy CA`. `ssh`/`openssl` ignore `HTTPS_PROXY` and use the direct path; `curl` uses the CONNECT path. |
| Origin cert validated? | CONNECT path: **yes** (self-signed and expired origins rejected). Direct path: **no** (re-signed a self-signed origin and relayed data). |
| Non-HTTP bytes inside TLS | CONNECT path: **rejected** (`ECONNRESET`). Direct path: **passed** to origin. |
| WebSocket `101` + bidirectional frames | **Works on both paths** (the proxy README's "WebSocket unsupported" is wrong empirically). |

So a bridge that must survive the stricter path needs: port 443, a
publicly-trusted certificate (→ a real domain), and HTTP/WebSocket framing.

---

## 1. Design decisions (DECIDED)

**D1 — Amend protocol v1; do not cut v2, do not add a second message.**
Insert `ssh_host_public_key` (STRING, authorized_keys two-field form,
`ssh-ed25519` only, ≤ 1024 bytes) as **field 5** of `CTX_HOST_REGISTER`,
immediately after `ssh_ca_public_key`; renumber 6–10. Record it in
`protocol/v1.md`'s header as the second pre-release amendment (precedent: the
`answer` removal). Zero external consumers exist. Field position is
cryptographically irrelevant (CBE encodes names); adjacency to the CA key is for
readability.

**D2 — The signer stores the host key at enrollment.** `grant-signer init` gains
`--ssh-host-key-file` (default `/etc/ssh/ssh_host_ed25519_key.pub`), reads it,
keeps fields 1–2 only, validates with `protocol.ParseSSHPublicKey`, stores it in
the `host` row. `HostRegistration()` refuses to produce a registration if it is
empty. Rotation = re-run `init` (it is idempotent: existing keys are kept,
enrollment is upserted) and restart `grantd.service` to force re-registration.
v1 pins exactly one ed25519 host key; the visitor forces
`HostKeyAlgorithms=ssh-ed25519`.

**D3 — HostDO stores and serves the exact signed registration + signature**,
mirroring what `publishGrant`/`grantRecord` already do for grants. The public
record's shape changes (see §2.4). A row written before this change has no
signed registration and is served as `404 HOST_NOT_FOUND` until the host
reconnects (it re-registers on every reconnect: `rendezvous.go:101-107`).

**D4 — The visitor verifies the host record *before* redeeming, and takes
`hostname`, `ssh_port`, `ssh_user`, `ssh_host_public_key` only from the verified
record.** The redemption response's `hostname`/`port`/`user` are not used (a
mismatch is logged to stderr, nothing more). Verifying first means a bad record
costs nothing; verifying after would burn a single-use grant on a transient
mismatch. The response's `certificate` is used as-is: it is CA-signed and a
substituted one simply fails at the real sshd.

**D5 — Pin via `HostKeyAlias=<host_id>`.** `known_hosts` contains one line,
`<host_id> ssh-ed25519 <base64>`. This makes the entry independent of
hostname/port/bracket formatting and of transport (Phase 3's `ProxyCommand`
reuses it unchanged).

**D6 — The visitor does not check the record's `timestamp` freshness.** Hosts
re-register on reconnect, so a record can legitimately be days old. A rolled-back
record is at worst a stale `hostname` — misrouting, which pinning turns into a
refused connection, never impersonation.

**D7 — Every visitor `ssh` invocation in the repository switches to the pinned
form, and CI enforces that no invocation carrying `CertificateFile=` carries
`StrictHostKeyChecking=no`.** Test-infrastructure ssh (root probes, droplet
provisioning — anything *without* `CertificateFile=`) is not a visitor and is
left alone.

**D8 — Go gets a visitor-side verifier in `go/agent`** so the verification logic
has a second implementation and can be tested against a hostile service in
Go. `install/redeem.sh` remains the shipped reference; both must agree with the
vectors.

**D9 — Phase 3 needs no protocol change.** Pinning makes the transport
security-irrelevant, so the visitor may *probe*: try direct TCP to
`hostname:ssh_port`; on failure, fall back to the bridge at
`https://<hostname>/ssh`. Whatever path reaches an sshd presenting the pinned
key is the right box.

**D10 — Per-host DNS names are `<b32>.hosts.grantd.dev`, where `<b32>` is
`host_id` with the `h_` prefix removed.** Underscores are prohibited in
certificate hostnames (CA/Browser Forum, SC12), so the `h_…` form proposed
earlier cannot obtain a public certificate. `[a-z2-7]{32}` is a valid label.

**D11 — TLS private keys never touch the service.** Hosts obtain their own
certificate (HTTP-01 via `certbot --webroot` against nginx on :80). The
service's only DNS job is publishing one `A` record per bridged host. No DNS
API credentials on hosts; no certificate pipeline at the service.

---

## 2. Phase 1 — Visitor-side verification (implementation-ready)

Ship as one PR. Suggested commit order keeps every commit green:
(a) protocol + Go + TS + vectors; (b) signer + init + installer/entrypoint;
(c) HostDO + worker tests; (d) `redeem.sh` + `cbe-vectors.sh`; (e) tests switched
to pinned path + CI lint + adversarial tests; (f) docs + README.

### 2.1 Protocol document — `protocol/v1.md`

1. Header: add a second amendment paragraph after the existing one, e.g.
   *"A second pre-release amendment added `ssh_host_public_key` to the host
   registration so that a visiting agent can verify the machine it connects
   to. Vectors regenerated; all three implementations re-verified."*
2. §4.1 table: insert row `| 5 | ssh_host_public_key | STRING | authorized_keys
   format, ssh-ed25519; the sshd host key a visitor must see |`, renumber
   `hostname`…`nonce` to 6–10. Update the idempotency sentence: re-registering
   also updates `ssh_host_public_key`.
3. §10 endpoints: describe `GET /v1/hosts/:host_id` as returning the signed
   registration (shape in §2.4 below). Add a short "Public host record" JSON
   example.
4. New §7a (or §14) **"Visitor-side verification (normative)"**, listing in
   order: (1) parse `host_id` from the capability URL; (2) `GET /v1/hosts/<host_id>`;
   (3) `registration.host_id == host_id` from the URL; (4) `host_id ==
   "h_" + b32(sha256(registration.identity_public_key)[0:20])`; (5)
   `registration.version == 1`; (6) Ed25519 signature verifies over
   `CBE(CTX_HOST_REGISTER, registration)`; (7) `ssh_host_public_key` parses as
   a two-field `ssh-ed25519` line; (8) connect with the exact ssh options in
   §2.5 step 8. State explicitly that `hostname`/`port`/`user` in the redemption
   response are informational and MUST NOT override the verified record.
5. §12 failure table: add *"Host registered before the host-key amendment →
   `HOST_NOT_FOUND` on the public record until the host reconnects."*
6. §0 trust table, "Visiting agent" row, add a sentence: it trusts the service
   for nothing, and verifies the host against the identity key its capability
   URL commits to.

### 2.2 Go protocol + vectors

`go/internal/protocol/messages.go`
- `HostRegistration`: add `SSHHostPublicKey string \`json:"ssh_host_public_key"\``
  after `SSHCAPublicKey`.
- `Canonical()`: add `canonical.S("ssh_host_public_key", m.SSHHostPublicKey)`
  immediately after the `ssh_ca_public_key` field.
- `hostRegistrationJSON`, `MarshalJSON`, `UnmarshalJSON`: add the field.

`go/internal/protocol/validate.go` (or `sshkey.go`): no new function needed;
callers use `ParseSSHPublicKey` (already rejects comments, extra fields, non-ed25519).

`go/cmd/protocol-vectors/main.go`
- Add `hostSSHSeed = mustHex("0404…04")` (32 bytes of `0x04`), derive
  `hostSSHLine := sshLine(ed25519.NewKeyFromSeed(hostSSHSeed).Public())`.
- Add `"host_ssh_seed_hex"` to `Keys` and `"host_ssh_public_key"` to `SSHKeys`.
- Set `SSHHostPublicKey: hostSSHLine` on both `reg` and `unicodeReg`.
- Regenerate: `cd go && go run ./cmd/protocol-vectors ../protocol/test-vectors/v1.json`
  (check the exact invocation in `.github/workflows/ci.yml:43-50` — CI diffs the
  committed file against a fresh generation, so the committed file must match).

`go/internal/vectors/vectors_test.go`: no change needed (decodes via
`UnmarshalJSON`), but confirm it still passes and that the vector JSON for
`host_registration` now shows `ssh_host_public_key`.

### 2.3 Signer, init, installer, e2e entrypoint

`go/signer/store/store.go`
- Schema: add `ssh_host_public_key TEXT NOT NULL DEFAULT ''` to `CREATE TABLE host`.
- Migration for existing DBs: after the schema exec, run a guarded
  `ALTER TABLE host ADD COLUMN ssh_host_public_key TEXT NOT NULL DEFAULT ''`
  (check `PRAGMA table_info(host)` first; SQLite has no `ADD COLUMN IF NOT EXISTS`).
- `Host` struct: add `SSHHostPublicKey string`. `SetHost` writes it (and the
  `ON CONFLICT` clause updates it). `Host()` scans it.

`go/signer/signer.go`
- `Enroll(ctx, sshUser, hostname string, port uint64, sshHostKeyLine string)`:
  validate with `protocol.ParseSSHPublicKey(sshHostKeyLine)`; reject empty.
- `HostRegistration()`: set `SSHHostPublicKey: h.SSHHostPublicKey`; if empty,
  return an error `"host has no ssh host key on record; re-run grant-signer init"`.
  This is the guard that makes it impossible to publish an unpinnable record.

`go/cmd/grant-signer/main.go`
- `cmdInit`: add `hostKeyFile := fs.String("ssh-host-key-file",
  envOr("GRANTD_SSH_HOST_KEY_FILE", "/etc/ssh/ssh_host_ed25519_key.pub"), …)`.
  Read it; take the first two whitespace-separated fields (the file normally has
  a third, the comment); pass to `Enroll`. Fail with a clear message naming the
  path if missing/unreadable/not ed25519. Include `ssh_host_public_key` in the
  printed JSON.
- `cmdStatus` and `api/http.go` `status`: include `ssh_host_public_key`.

`go/signer/signer_test.go`: update every `Enroll` call; add cases: comment-bearing
line is rejected, `ssh-rsa` rejected, empty rejected, `HostRegistration()` errors
when the stored key is empty, and the produced registration verifies and
contains the key. Update the fixture in `go/tests/adversarial` harness
(`newHarness`, ~line 203) the same way.

`install/install.sh`
- Preflight (next to the `sshd_config.d` Include check): `[ -r
  /etc/ssh/ssh_host_ed25519_key.pub ] || die "no ed25519 host key at
  /etc/ssh/ssh_host_ed25519_key.pub; run 'ssh-keygen -A' as root and re-run"`.
  Do **not** generate it: the installer's contract is to touch sshd minimally.
- No flag change needed (default path). Print the host key fingerprint in the
  final summary (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`).

`tests/e2e/entrypoint.sh`: move `ssh-keygen -A >/dev/null` to **before**
`grant-signer init` (currently it runs after, at the "validating sshd
configuration" step, so the key would not exist at enrollment).

`tests/install/run.sh`, `tests/vm/run.sh`, `.github/workflows/ci.yml` (the
"prepare an sshd" step, ~line 91): confirm the ed25519 host key exists before
the installer runs; add `ssh-keygen -A` to the preparation step where the image
is built from a minimal base. Ubuntu cloud images and the Debian `openssh-server`
package normally generate it; the e2e Dockerfile does not.

### 2.4 Coordination service — HostDO and tests

`cloudflare/src/protocol.ts`
- `HostRegistration` interface: add `ssh_host_public_key: string` after
  `ssh_ca_public_key`.
- `parseHostRegistration`: `ssh_host_public_key: str(o, "ssh_host_public_key",
  MAX_SSH_PUBKEY_BYTES)`; validate with the same regex used for
  `ssh_public_key` in `parseRedemptionPayload`
  (`/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$/`), `bad("ssh_host_public_key must be a
  two-field ssh-ed25519 authorized_keys line")`.
- `hostRegistrationFields`: add `S("ssh_host_public_key", m.ssh_host_public_key)`
  right after the CA key field.

`cloudflare/src/durable-objects/host.ts`
- Schema: add to `host`: `ssh_host_public_key TEXT NOT NULL DEFAULT ''`,
  `signed_registration TEXT NOT NULL DEFAULT ''`, `signature TEXT NOT NULL
  DEFAULT ''`. Add a guarded `ALTER TABLE … ADD COLUMN` for each in `migrate()`
  (production DOs exist; `CREATE TABLE IF NOT EXISTS` will not add columns).
- `register()`: after verification, store `JSON.stringify(serializeHostRegistration(reg))`
  — a `serializeHostRegistration` helper analogous to `serializeGrant`, emitting
  keys **in CBE field order** with binary fields base64url — and
  `b64uEncode(signature)`. Update both the `UPDATE` and `INSERT`.
- `publicRecord()`: if `signed_registration` is empty → `errorResponse(ERR.HOST_NOT_FOUND,
  "host record predates signed records; it is republished when the host reconnects")`.
  Otherwise return exactly:
  ```json
  {
    "registration": { …the stored object, 10 keys in CBE order… },
    "signature": "<base64url, 64 bytes>",
    "connected": true,
    "created_at": 0,
    "last_seen_at": 0
  }
  ```
  **No registration key may be repeated at top level** (drop the current flat
  `host_id`, `hostname`, `protocol_version`, etc.). `redeem.sh` extracts fields
  by name with a deliberately naive matcher; uniqueness of each key in the
  document is what makes that safe, and the worker test below pins it.
- `grantRecord()`: keep its `host: {hostname, ssh_port, ssh_user}` convenience
  block unchanged (informational; the visitor does not use it).
- `hostRow()` typing: add the three columns.

`cloudflare/test/helpers.ts` `registrationBody()` (~line 83): add
`ssh_host_public_key` to the registration (generate a fixed ed25519 line, e.g.
from a seed, or reuse the vectors' `host_ssh_public_key`) and to the overrides type.

`cloudflare/test/worker.test.ts`, new cases:
1. `GET /v1/hosts/:id` after registration returns `registration` + `signature`;
   `verifyEd25519(identity, canonicalHostRegistration(parseHostRegistration(body.registration)), b64uDecode(body.signature))` is `true`.
2. `hostId(registration.identity_public_key) === registration.host_id`.
3. No top-level key of the response equals any key of `registration` (iterate
   `Object.keys`).
4. A registration with `ssh_host_public_key` = `"ssh-rsa AAAA…"`, or with a
   comment, or missing, is rejected `BAD_REQUEST`.
5. The existing tamper test (~line 125, `hostname = "attacker.example.com"`)
   still fails `BAD_SIGNATURE`; add the same for a tampered `ssh_host_public_key`.
6. A row with empty `signed_registration` (simulate by registering, then
   `sql.exec("UPDATE host SET signed_registration=''")` via a test hook, or by
   asserting the branch with a unit test on the DO) returns `HOST_NOT_FOUND`.

`cloudflare/test/vectors.test.ts` `canonicalFor`: add
`ssh_host_public_key: s(m.ssh_host_public_key)` to the `CTX_HOST_REGISTER` case.

`cloudflare/src/routes/docs.ts`: see §2.6.

### 2.5 The shipped visitor — `install/redeem.sh`

All new helpers go **before** `raw_pubkey_hex()` in the file:
`tests/e2e/cbe-vectors.sh` evals the helper block with
`sed -n '/^hexof()/,/^raw_pubkey_hex()/p'`, so helpers placed later are invisible
to the vector check. Keep strict POSIX `sh`; no `jq`, no bash.

New helpers:
```sh
# host_id = "h_" || base32(sha256(pub)[0:20])   (mirror of agent_id_of)
host_id_of() { _d="$(unhex "$1" | "$OPENSSL" dgst -sha256 -binary | LC_ALL=C od -An -tx1 -v -N 20 | tr -d ' \n')"; printf 'h_%s' "$(b32_from_hex "$_d")"; }

# Ed25519 SubjectPublicKeyInfo: fixed 12-byte DER prefix || 32 raw key bytes.
#   30 2a 30 05 06 03 2b 65 70 03 21 00
spki_pem_from_raw_hex() { # <32-byte pubkey hex> -> PEM on stdout
  { printf -- '-----BEGIN PUBLIC KEY-----\n'
    unhex "302a300506032b6570032100$1" | "$OPENSSL" base64 -A; printf '\n'
    printf -- '-----END PUBLIC KEY-----\n'; }
}

ed25519_verify_hex() { # <pubkey hex> <message hex> <signature hex> -> exit 0 iff valid
  _pub="$(mktemp)"; _msg="$(mktemp)"; _sig="$(mktemp)"
  spki_pem_from_raw_hex "$1" > "$_pub"; unhex "$2" > "$_msg"; unhex "$3" > "$_sig"
  "$OPENSSL" pkeyutl -verify -pubin -inkey "$_pub" -rawin -in "$_msg" -sigfile "$_sig" >/dev/null 2>&1
  _rc=$?; rm -f "$_pub" "$_msg" "$_sig"; return $_rc
}
```

Flow change — insert a new section **immediately after the capability-URL
parsing block** (after the three `echo "host:/grant:/origin:"` lines) and before
the identity/registration section, so a bad record fails before any proof of
work and before any grant could be spent:

1. `REC="$(http GET "$ORIGIN/v1/hosts/$HOST_ID")"`.
2. Extract with `json_str`/`json_num`: `version`, `host_id`, `identity_public_key`,
   `ssh_ca_public_key`, `ssh_host_public_key`, `hostname`, `ssh_port`, `ssh_user`,
   `timestamp`, `nonce`, `signature`. (`json_str` cannot handle a value
   containing `"`; none of these can contain one — `hostnameRe` and the ssh-key
   regex forbid it — and a mis-extraction simply fails verification. Fail-closed.)
3. `[ "$REC_HOST_ID" = "$HOST_ID" ] || die "host record is for $REC_HOST_ID, not $HOST_ID"`.
4. `IDPK_HEX="$(b64u_decode_hex "$REC_IDPK")"`; `[ ${#IDPK_HEX} -eq 64 ]`;
   `[ "$(host_id_of "$IDPK_HEX")" = "$HOST_ID" ] || die "identity key does not hash to $HOST_ID"`.
5. `[ "$REC_VERSION" = 1 ]`.
6. Build `REG_CBE="$(cbe 'grantd/v1/host-register' 10 $(f_u64 version 1) $(f_string host_id …) $(f_bytes identity_public_key "$IDPK_HEX") $(f_string ssh_ca_public_key …) $(f_string ssh_host_public_key …) $(f_string hostname …) $(f_u64 ssh_port …) $(f_string ssh_user …) $(f_u64 timestamp …) $(f_bytes nonce "$(b64u_decode_hex "$REC_NONCE")"))"`
   — pass fields as separate arguments in exactly this order.
7. `ed25519_verify_hex "$IDPK_HEX" "$REG_CBE" "$(b64u_decode_hex "$REC_SIG")" || die "host record signature does not verify; refusing to continue"`.
8. `case "$REC_HOSTKEY" in "ssh-ed25519 "*) ;; *) die "host key is not ssh-ed25519";; esac`
   and check it has exactly two fields (`set -- $REC_HOSTKEY; [ $# -eq 2 ]`).
9. Set `HOSTNAME="$REC_HOSTNAME" PORT="$REC_PORT" USER="$REC_USER"` — these are
   now the **only** source of connection details. Echo `hostkey: SHA256:…`
   (compute with `openssl` from the base64 blob, or skip the fingerprint) to stderr.
10. Write `$OUT/known_hosts` as one line: `printf '%s %s\n' "$HOST_ID" "$REC_HOSTKEY"`
    (mode 0600).

After redemption:
- Stop assigning `USER`/`HOSTNAME`/`PORT` from `$RESP`. If they differ from the
  record, `echo "warning: service response names $x, verified record names $y; using the record" >&2`.
- `--connect` exec and the printed command both become exactly:
  ```
  ssh -i "$OUT/id_ed25519" \
      -o CertificateFile="$OUT/id_ed25519-cert.pub" \
      -o IdentitiesOnly=yes \
      -o UserKnownHostsFile="$OUT/known_hosts" \
      -o StrictHostKeyChecking=yes \
      -o HostKeyAlias="$HOST_ID" \
      -o HostKeyAlgorithms=ssh-ed25519 \
      -p "$PORT" "$USER@$HOSTNAME"
  ```

`tests/e2e/redeem.sh` is a tracked byte-for-byte copy regenerated by
`tests/e2e/run.sh:58`; after editing `install/redeem.sh`, copy it over and commit both.

`tests/e2e/cbe-vectors.sh`, add checks (inside `run_checks`, so they run in both locales):
- `host_registration` canonical bytes: encode the 10 fields from the vector's
  `message` with `cbe … 10` and compare to `canonical_hex`.
- `host_id_of` of `keys.host_identity_pub_hex` equals `identifiers.host_id`.
- `ed25519_verify_hex host_identity_pub_hex canonical_hex signature_hex` succeeds,
  and fails when the last hex digit of the signature is flipped. This proves the
  SPKI construction and `pkeyutl -verify` work on the target OpenSSL.
- Extend the `eval` range comment if new helper names fall outside it (they
  should not, per the placement rule above).

### 2.6 Agent-facing docs — `cloudflare/src/routes/docs.ts`

`grantInstructions`: add a step **before** the current step 1:
*"0. Fetch and verify the host record: `curl ${origin}/v1/hosts/${hostId}`.
Check `registration.host_id == ${hostId}`; check `${hostId} == "h_" +
base32(sha256(registration.identity_public_key)[0:20])`; verify `signature`
over `CBE("grantd/v1/host-register", registration)` with that key. Take
hostname, port, user, and `ssh_host_public_key` from this record and nothing
else. If any check fails, stop — the service may be routing you to a machine
that is not the one your capability names."* Replace step 6's ssh command with
the pinned form (write `known_hosts` as `<host_id> <ssh_host_public_key>`).
Add to Notes: the `hostname`/`port`/`user` in the redemption response are
informational.

`docsMarkdown`: endpoint line for `GET /v1/hosts/:host_id` → "signed public host
record (verify it)". Add one paragraph under a new heading "What you can verify":
the service can misroute you but cannot impersonate a host, provided you verify
the record and pin the host key.

### 2.7 Tests switched to the pinned path, CI lint, new adversarial coverage

Replace the visitor `ssh` invocation (the one with `CertificateFile=`) in each of:
`tests/e2e/run.sh:136`, `tests/remote/run.sh:191,203,229`, `tests/vm/run.sh:130,254`,
`tests/install/run.sh:169,196`, `tests/install/release.sh:173`,
`.github/workflows/ci.yml:158` — with the pinned options from §2.5 step 8, using
the `known_hosts` that `redeem.sh --out DIR` wrote to `DIR/known_hosts` and
`HostKeyAlias=<host_id>`. Where the test hand-rolls the visitor (e.g. the
"leftover certificate after uninstall" checks), it must still pin: those checks
assert the *certificate* is refused, and must not pass because the *host key*
was refused first — so keep the pinned known_hosts from the earlier successful
login for those.

Leave alone: `tests/install/run.sh:68` (root probe), `tests/remote/digitalocean.sh:90,109`
(provisioning ssh to the droplet). They are not visitors.

`tests/e2e/run.sh`, add:
- After the successful login: run the exact command `redeem.sh` printed, plus
  `-o BatchMode=yes`, expecting success. `BatchMode` forbids prompts, so this
  proves the flow works with no tty (the original bug).
- Negative: copy `known_hosts`, replace the key with a different valid ed25519
  key (`ssh-keygen -t ed25519 -N '' -f /tmp/wrong` and use `/tmp/wrong.pub`),
  run ssh with `UserKnownHostsFile` pointing at the copy → must fail, and stderr
  must contain `Host key verification failed` or `REMOTE HOST IDENTIFICATION HAS CHANGED`.
  This catches any regression back to `StrictHostKeyChecking=no`.
- Negative: alter one character inside the `signature` of a saved host record
  and feed it to `redeem.sh` — not directly possible against a live DO; instead
  cover this in Go (below) and add an e2e assertion that `redeem.sh` refuses a
  capability URL whose `host_id` is a *different* registered host's id than the
  grant's (mint on host A; rewrite the URL's host_id to a syntactically valid
  unknown id → `HOST_NOT_FOUND` from `/v1/hosts/`, exit non-zero, *no*
  registration or redemption attempted — assert no `agent.registered` /
  `grant.redemption_requested` for that run in the worker logs if reachable,
  otherwise assert the error text names the host record step).

CI lint (new step in the `go` or `worker` job; a 10-line script under
`tests/lint/`): join shell continuation lines (`\`+newline) and fail if any
line contains both `CertificateFile=` and `StrictHostKeyChecking=no`, or
`CertificateFile=` and `UserKnownHostsFile=/dev/null`, across `tests/`,
`install/`, `.github/`, `cloudflare/src/routes/docs.ts`, `README.md`.

Go — `go/agent`:
- New file `verify.go`: `type PublicHostRecord struct { Registration
  protocol.HostRegistration; Signature []byte; … }` with JSON decoding matching
  §2.4, and `func VerifyHostRecord(hostIDFromURL string, rec PublicHostRecord)
  (protocol.HostRegistration, error)` implementing §2.1 steps 3–7 and returning
  distinct sentinel errors (`ErrRecordHostMismatch`, `ErrIdentityMismatch`,
  `ErrBadRecordSignature`, `ErrBadHostKey`, `ErrBadVersion`).
- `func KnownHostsLine(hostID string, reg protocol.HostRegistration) string`
  returning `<host_id> <ssh_host_public_key>\n`.
- Unit tests: a record built from the vectors verifies; each tamper (hostname,
  host key, identity key, signature, host_id) fails with the right sentinel.
- Adversarial: in `go/tests/adversarial/hostile_service_test.go`, add
  `TestHostileServiceCannotRedirectTheVisitor` using the existing
  `newHostileService`/`newHarness`: serve `GET /v1/hosts/<id>` from the hostile
  service with (a) the genuine record; (b) a record whose `hostname` is
  replaced but signature unchanged; (c) a valid record signed by a *different*
  identity key (a second harness) served under the first host's id; (d) the
  genuine registration with a fresh random signature. Only (a) verifies. Also
  assert (e): a redemption response carrying a different `hostname` does not
  change what `VerifyHostRecord` returned — i.e. the visitor path in Go ignores
  it (write the visitor flow helper so the test can call it end to end).

### 2.8 README

- "Security model": add invariant 8: *"A visiting agent verifies the machine it
  connects to against an SSH host key that the host signed with the identity
  key its capability URL names. A compromised coordination service can refuse
  to route a visitor; it cannot send one to a machine it controls."*
- "How it works" step 5: "The agent verifies the host's signed record, pins its
  host key, and connects directly…".
- "The whole thing in two commands": show the printed ssh command with the
  pinned options; mention `known_hosts` is written next to the key.
- "For agents": one sentence pointing at the verification step.
- "Status": drop the implicit claim that visitors are protected only by the
  certificate; state what is now verified.

### 2.9 Acceptance criteria — Phase 1 is done when all of these hold

```
cd go && go vet ./... && go test ./... -timeout 10m          # green
cd go && go run ./cmd/protocol-vectors /tmp/v.json && diff -q /tmp/v.json ../protocol/test-vectors/v1.json   # identical
cd cloudflare && npm ci && npm run typecheck && npm test      # green
sh tests/e2e/cbe-vectors.sh install/redeem.sh protocol/test-vectors/v1.json   # ok in C and UTF-8
tests/lint/visitor-ssh-pinned.sh                              # no violations
tests/e2e/run.sh                                              # green, incl. BatchMode + wrong-key negatives
diff -q install/redeem.sh tests/e2e/redeem.sh                 # identical
grep -c "StrictHostKeyChecking=no" install/redeem.sh cloudflare/src/routes/docs.ts README.md   # 0 each
```
plus: `install/install.sh` refuses a host without an ed25519 host key with a
message naming the path; CI (`.github/workflows/ci.yml`) green on all jobs.

Environment notes for whoever runs this: the sandbox used to write this plan had
`go 1.24.7` (go.mod says 1.25.0 — `GOTOOLCHAIN=auto` fetches it via
`proxy.golang.org`, which is reachable), `node 22`, `docker`, `jq`, `openssl 3.0`,
but **no `ssh`/`ssh-keygen`** (`apt-get install -y openssh-client` first) and no
`node_modules` (`npm ci`). If Docker cannot run nested, leave `tests/e2e`,
`tests/install`, `tests/vm` to CI and say so.

### 2.10 Out of scope for Phase 1 (do not do)

- Any change to `Redeem()`, `ClaimGrant`, single-use semantics, nonce handling,
  the CBE encoder, the frame vocabulary, or the daemon socket API surface.
- Host *certificates* (`HostCertificate`/`@cert-authority`) — v1 pins one raw key.
- Generating host keys in the installer.
- Checking the host record's `timestamp` on the visitor (D6).
- Skipping, disabling, or loosening any existing test.

---

## 3. Phase 2 — Domain and service origin (design-ready)

Prerequisite: Phase 1 merged. Owner already holds `grantd.dev` (GoDaddy; parked).

1. **Move DNS to Cloudflare.** Add the zone in the Cloudflare account that hosts
   the Worker; change nameservers at GoDaddy. Every record created below is
   **DNS-only (grey cloud)**. A proxied (orange) record would put Cloudflare in
   the SSH data path and falsify the "never proxied" claim.
2. **Service origin.** `wrangler.jsonc`: add
   `"routes": [{ "pattern": "api.grantd.dev", "custom_domain": true }]` and set
   `vars.PUBLIC_ORIGIN` to `https://api.grantd.dev`. Update README examples,
   `docs.ts` (it already takes `origin`), `.github/workflows/ci.yml:22`. Leave
   `grantd.example.workers.dev` in `protocol/v1.md` §6 and the vectors — it is
   illustrative and changing it churns the vectors for nothing. Existing
   enrolled hosts must be re-inited with the new `--origin` (zero users; note
   in the changelog).
   **DECISION NEEDED:** `api.grantd.dev` vs bare `grantd.dev`. Recommendation:
   `api.` — keeps the apex free for a landing page later and keeps host names
   under a sibling label.
3. **Per-host names** (D10): `<b32>.hosts.grantd.dev`. Add
   `protocol.HostDNSLabel(hostID) string` (strip `h_`) in Go and TS; the
   installer's new `--bridge` mode (Phase 3) sets `--hostname` to that name.
4. **A-record publication.** In `HostDO.register()`, if `env.HOST_ZONE_ID` and
   `env.CF_DNS_TOKEN` (a Worker secret scoped to *DNS:Edit on that one zone*)
   are set **and** `reg.hostname` equals the derived per-host name, upsert an
   `A` record for it pointing at the request's `CF-Connecting-IP`. Do this
   `ctx.waitUntil`-style so registration latency is unaffected; log
   `dns.published`. Behind NAT the IP is wrong and harmless — the bridge is for
   publicly reachable hosts only; a NAT'd host keeps a raw address in `hostname`
   and gets no record. Never publish a record for a `hostname` the host did not
   sign. **DECISION NEEDED:** source-IP vs a new signed `advertised_ip` field.
   Recommendation: source IP; it needs no protocol change and the signed
   `hostname` is what the visitor pins against anyway.
5. **Worker tests:** DNS publication is called only for the derived name; not
   called when env is unset; failure to publish does not fail registration.
6. **Self-hosting note in README:** a self-hosted service without a zone works
   exactly as today; only bridged hosts need a zone.

Not needed, explicitly: DNS-01, a certificate pipeline at the service, DNS
credentials on hosts (D11).

## 4. Phase 3 — The 443 bridge (design-ready)

Prerequisites: Phases 1–2. Off by default. Nothing in this phase changes the
protocol (D9).

**Host side** — a separate, opt-in `install/bridge.sh` (keeps `install.sh`'s
sshd-touching surface unchanged):
1. Installs distro `nginx` and `certbot`. Obtains a certificate for
   `<b32>.hosts.grantd.dev` with `certbot certonly --webroot` served by nginx on
   :80 (`/.well-known/acme-challenge/` only; everything else on :80 → 301 to
   https). Key stays on the host; certbot's timer renews.
2. Builds/installs `grantd-bridge` — **DECIDED:** a Go binary in this repo
   (`go/cmd/grantd-bridge`) using `github.com/coder/websocket` (already a
   dependency), shipped through the existing signed-release pipeline. It listens
   on `127.0.0.1:<port>` only, upgrades to WebSocket, and copies bytes to a
   target that is **compiled in as `127.0.0.1:22`** — no flag, no header, no
   path may influence it. After the upgrade it parses nothing. Alternative
   considered and rejected: `websocat`/`wstunnel` (not in Debian main; would
   bypass the release signing story).
3. systemd unit for the bridge: own user `grantdbridge`, copy the hardening
   block from `grantd.service` verbatim, `RestrictAddressFamilies=AF_INET AF_INET6`,
   `IPAddressAllow=127.0.0.0/8` + `IPAddressDeny=any`.
4. nginx server block on :443: TLS from certbot, `location = /ssh` →
   `proxy_pass http://127.0.0.1:<port>` with `proxy_http_version 1.1`,
   `Upgrade`/`Connection` headers, `proxy_read_timeout 1h` (idle sessions),
   `limit_conn` (per-IP, e.g. 8) and `limit_req` on the upgrade location; every
   other location → 404. Access log: IP, time, status only.
5. Document: sshd will see all bridged sessions from `127.0.0.1`; source-IP
   controls (fail2ban, `MaxStartups` per source, sshd logs) are meaningless for
   bridged sessions; nginx's log and limits replace them.

**Visitor side** — `install/redeem.sh` and `docs.ts`:
1. After verifying the record, probe `hostname:ssh_port` with a short TCP
   connect (`exec 3<>/dev/tcp/…` is bash-only; in POSIX sh use
   `curl -s --connect-timeout 5 telnet://host:port </dev/null` or an `ssh -o
   ConnectTimeout=5` dry run). On success: direct, exactly as Phase 1.
2. On failure: `ProxyCommand` to a WebSocket↔stdio shim. **DECIDED:** a
   stdlib-only python3 script (`socket`, `ssl`, `os`, `base64`, `hashlib`; ~80
   lines) served as `GET /bridge-proxy.py` from the Worker (same single-copy
   pattern as `redeem.sh`) and fetched by `redeem.sh` when needed. Rationale:
   `redeem.sh` already reaches for python3 (proof of work) and the project has
   ruled out client binaries. It must verify the origin cert against the
   system store by default; `GRANTD_BRIDGE_INSECURE_TLS=1` disables that for
   self-signed/Tier-A hosts and prints a warning. Honour `HTTPS_PROXY` (CONNECT)
   when set, falling back to direct.
3. The ssh command is unchanged except for `-o ProxyCommand="python3
   bridge-proxy.py wss://$HOSTNAME/ssh"`; `HostKeyAlias=$HOST_ID` and the same
   `known_hosts` keep pinning identical across transports.
4. Tests: `tests/remote/run.sh` gains a `--bridge` mode that runs the visitor
   with port 22 blocked locally (`iptables` in a container, or simply pass
   `--force-bridge`) and asserts login *and* that the pinned key still gates it
   (wrong-key negative through the bridge).

**Tier A (documented, not shipped):** nginx `stream` with a self-signed cert
proxying TLS→`127.0.0.1:22`, visitor `ProxyCommand openssl s_client -quiet
-connect %h:443`. Works today on the sandbox's direct path (no cert validation,
no HTTP enforcement there), zero client dependencies, ~20 lines. It depends on
undocumented gateway leniency and fails on any CONNECT-only path, so it is a
demo, not a product path. Mention it in `docs/` as an experiment; do not add it
to the installer.

---

## 5. Guardrails for the executing agent

- Do not weaken any existing invariant to make a test pass. If a Phase-1 change
  breaks a test in `go/tests/adversarial`, the change is wrong, not the test.
- `install/redeem.sh` stays POSIX `sh`, with only `curl`, `openssl`, `ssh`,
  `ssh-keygen`, `od`, `sed`, `tr`, `awk`, `mktemp`; python3 only where it already
  is (proof of work) and, in Phase 3, the bridge proxy.
- Never log or echo a capability secret, a `proof`, or a private key — including
  in new error messages and test output.
- Keep `HostDO` free of secrets. The DNS token in Phase 2 is a Worker secret
  scoped to one zone's DNS; it is the first credential the service holds and
  the README must say so.
- One PR per phase. Phase 1's PR description must list the eight invariants
  and state that #8 is new.
- Commit messages: describe the behaviour change and why, in the style of the
  existing log (`git log --oneline -12`).
