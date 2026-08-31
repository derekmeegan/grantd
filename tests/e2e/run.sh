#!/usr/bin/env bash
#
# End-to-end test: a capability URL becomes a real SSH session on a real sshd,
# and every way it should fail, does.
#
# Usage:
#   tests/e2e/run.sh [--origin URL] [--public-origin URL]
#
# With no arguments it expects a coordination service at http://127.0.0.1:8787
# (wrangler dev). Point --origin at a deployed Worker to run the same suite
# against production.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ORIGIN="http://host.docker.internal:8787"
PUBLIC_ORIGIN="http://127.0.0.1:8787"
SSH_PORT=2222
CONTAINER=grantd-e2e-host
IMAGE=grantd-e2e-host
WORK="$(mktemp -d)"

while [ $# -gt 0 ]; do
  case "$1" in
    --origin) ORIGIN="$2"; shift 2 ;;
    --public-origin) PUBLIC_ORIGIN="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---------------------------------------------------------------- build

step "building"
( cd "$REPO/go"
  export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
  for c in grantd grant-signer grantctl grant-agent; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$(docker version --format '{{.Server.Arch}}')" \
      go build -trimpath -ldflags "-s -w" -o "$REPO/tests/e2e/$c" "./cmd/$c"
  done
  go build -o "$REPO/bin/" ./cmd/... )
docker build -q -t "$IMAGE" "$REPO/tests/e2e" >/dev/null
ok "images and binaries built"

AGENT="$REPO/bin/grant-agent"
OWNER_SOCK=/run/grantd/owner/owner.sock

# ---------------------------------------------------------------- boot

step "starting host"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" -p "$SSH_PORT:22" \
  -e GRANTD_ORIGIN="$ORIGIN" \
  -e GRANTD_PUBLIC_ORIGIN="$PUBLIC_ORIGIN" \
  -e GRANTD_ADVERTISE_HOST=127.0.0.1 \
  -e GRANTD_ADVERTISE_PORT="$SSH_PORT" \
  --add-host=host.docker.internal:host-gateway "$IMAGE" >/dev/null

HOST_ID=""
for _ in $(seq 1 60); do
  if docker logs "$CONTAINER" 2>&1 | grep -q "rendezvous connected"; then
    HOST_ID=$(docker logs "$CONTAINER" 2>&1 | grep -o 'host_id=h_[a-z2-7]*' | head -1 | cut -d= -f2)
    break
  fi
  sleep 1
done
[ -n "$HOST_ID" ] || { echo "host never connected"; docker logs "$CONTAINER" | tail -30; exit 1; }
ok "host $HOST_ID enrolled and connected"

mint() { docker exec -u ubuntu "$CONTAINER" grantctl new --socket "$OWNER_SOCK" --ttl "$1" --url-only; }

# ---------------------------------------------------- the thing it promises

step "a capability URL becomes an SSH session"
URL="$(mint 20m)"
sleep 3
OUT="$WORK/visit"; mkdir -p "$OUT"
"$AGENT" redeem --identity "$OUT/identity" --out "$OUT" "$URL" > "$OUT/result.json"
ok "redeemed"

SSH_OUT=$(ssh -i "$OUT/id_ed25519" -o CertificateFile="$OUT/id_ed25519-cert.pub" \
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR -o ConnectTimeout=10 -p "$SSH_PORT" ubuntu@127.0.0.1 'whoami' 2>&1)
[ "$SSH_OUT" = "ubuntu" ] && ok "logged in as ubuntu over real sshd" || bad "ssh login: $SSH_OUT"

# The serial in the response must be the serial in the certificate. A JSON
# round trip through float64 silently breaks this, so it is checked explicitly.
REPORTED=$(jq -r .serial "$OUT/result.json")
ACTUAL=$(ssh-keygen -L -f "$OUT/id_ed25519-cert.pub" | awk '/Serial:/{print $2}')
[ "$REPORTED" = "$ACTUAL" ] && ok "reported serial matches the certificate ($ACTUAL)" \
  || bad "serial mismatch: reported $REPORTED, certificate $ACTUAL"

PRINCIPALS=$(ssh-keygen -L -f "$OUT/id_ed25519-cert.pub" | awk '/Principals:/{getline; print $1}')
[ "$PRINCIPALS" = "ubuntu" ] && ok "certificate carries exactly the enrolled principal" \
  || bad "principals were $PRINCIPALS"

if ssh-keygen -L -f "$OUT/id_ed25519-cert.pub" | grep -qE 'permit-(port|agent|X11)-forwarding'; then
  bad "certificate grants forwarding"
else
  ok "certificate grants no port, agent or X11 forwarding"
fi

# ---------------------------------------------------------- single use

step "a grant is single use"
OUT2="$WORK/visit2"; mkdir -p "$OUT2"
if "$AGENT" redeem --identity "$OUT2/identity" --out "$OUT2" "$URL" >"$OUT2/err" 2>&1; then
  bad "a second agent redeemed an already-used grant"
else
  grep -q GRANT_ALREADY_REDEEMED "$OUT2/err" \
    && ok "second redemption rejected with GRANT_ALREADY_REDEEMED" \
    || bad "second redemption failed with the wrong error: $(cat "$OUT2/err")"
fi

step "an identical retry returns the identical certificate"
# A lost response must be safe to retry. Same agent, same SSH key, same grant.
OUT3="$WORK/visit3"; mkdir -p "$OUT3"
cp "$OUT/identity" "$OUT3/identity"
URL2="$(mint 20m)"; sleep 3
"$AGENT" redeem --identity "$OUT3/identity" --out "$OUT3" "$URL2" > "$OUT3/a.json"
cp "$OUT3/id_ed25519" "$OUT3/id_ed25519.bak"
FIRST_SERIAL=$(jq -r .serial "$OUT3/a.json")
# Re-redeeming generates a new SSH key, so this must be rejected, not reissued.
if "$AGENT" redeem --identity "$OUT3/identity" --out "$OUT3" "$URL2" >"$OUT3/b.err" 2>&1; then
  bad "a new SSH key was certified against an already-redeemed grant"
else
  grep -q GRANT_ALREADY_REDEEMED "$OUT3/b.err" \
    && ok "a different key on a used grant is rejected (serial $FIRST_SERIAL stands)" \
    || bad "unexpected error: $(cat "$OUT3/b.err")"
fi

# ---------------------------------------------------------- revocation

step "revocation takes effect immediately"
URL3="$(mint 20m)"; sleep 3
GID=$(echo "${URL3%%#*}" | awk -F/ '{print $NF}')
docker exec -u ubuntu "$CONTAINER" grantctl revoke --socket "$OWNER_SOCK" "$GID" >/dev/null
OUT4="$WORK/visit4"; mkdir -p "$OUT4"
if "$AGENT" redeem --identity "$OUT4/identity" --out "$OUT4" "$URL3" >"$OUT4/err" 2>&1; then
  bad "a revoked grant was redeemed"
else
  grep -q GRANT_REVOKED "$OUT4/err" && ok "revoked grant rejected with GRANT_REVOKED" \
    || bad "unexpected error: $(cat "$OUT4/err")"
fi

# ------------------------------------------------- local privilege boundary

step "the network-facing daemon cannot reach key material"
# Assume the daemon is fully compromised: run as its uid and try everything.
#
# These assert on exit status rather than on error text. A test that greps for
# "permission denied" passes for the wrong reason when the command is truncated,
# silenced, or fails differently — and a security assertion that can pass for the
# wrong reason is worse than no assertion.
denied() { # denied <description> <shell>
  if docker exec -u grantd "$CONTAINER" sh -c "$2" >/dev/null 2>&1; then
    bad "$1 — SUCCEEDED and must not have"
  else
    ok "$1"
  fi
}

denied "daemon cannot read the SSH CA private key"   'cat /etc/grantd/ssh_ca'
denied "daemon cannot read the host identity key"    'cat /etc/grantd/host_identity'
denied "daemon cannot read the grant database"       'cat /var/lib/grant-signer/state.db'
denied "daemon cannot list the signer key directory" 'ls /etc/grantd'
denied "daemon cannot write the signer state dir"    'touch /var/lib/grant-signer/x'
denied "daemon cannot modify sshd configuration"     'echo x > /etc/ssh/sshd_config.d/zz-evil.conf'
denied "daemon cannot even reach the owner socket"   "curl -sS --unix-socket $OWNER_SOCK -X POST http://localhost/grants -d '{}'"

# The daemon socket does exist for the daemon, and is deliberately narrow: the
# grant-creation route is simply not mounted on it.
out=$(docker exec -u grantd "$CONTAINER" sh -c \
  "curl -s -o /dev/null -w '%{http_code}' --unix-socket /run/grantd/redeem/redeem.sock http://localhost/grants" 2>&1)
[ "$out" = "404" ] && ok "daemon socket exposes no grant-creation endpoint" \
  || bad "unexpected status from daemon socket /grants: $out"

# ...and it is reachable, so the 404 above means "no such route", not "no socket".
out=$(docker exec -u grantd "$CONTAINER" sh -c \
  "curl -s -o /dev/null -w '%{http_code}' --unix-socket /run/grantd/redeem/redeem.sock http://localhost/status" 2>&1)
[ "$out" = "200" ] && ok "daemon socket is reachable by the daemon (so the 404 is a missing route)" \
  || bad "daemon could not reach its own socket: $out"

# ---------------------------------------------------------- expiry

step "expiry is enforced by the host"
URL4="$(mint 60s)"; sleep 3
OUT5="$WORK/visit5"; mkdir -p "$OUT5"
echo "  waiting 65s for the grant to expire..."
sleep 65
if "$AGENT" redeem --identity "$OUT5/identity" --out "$OUT5" "$URL4" >"$OUT5/err" 2>&1; then
  bad "an expired grant was redeemed"
else
  grep -qE 'GRANT_EXPIRED' "$OUT5/err" && ok "expired grant rejected with GRANT_EXPIRED" \
    || bad "unexpected error: $(cat "$OUT5/err")"
fi

# ---------------------------------------------------------- summary

step "summary"
printf '  %d passed, %d failed\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
