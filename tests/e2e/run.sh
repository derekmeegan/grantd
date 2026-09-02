#!/usr/bin/env bash
#
# End-to-end test: a capability URL becomes a real SSH session on a real
# sshd, and every way it must fail, does.
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
VISITOR=grantd-e2e-visitor
NET=grantd-e2e-net
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
  docker rm -f "$CONTAINER" "$VISITOR" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# --------------------------------------------------------------------- build

step "building"
( cd "$REPO/go"
  export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
  for c in grantd grant-signer; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$(docker version --format '{{.Server.Arch}}')" \
      go build -trimpath -ldflags "-s -w" -o "$REPO/tests/e2e/$c" "./cmd/$c"
  done )
cp "$REPO/install/redeem.sh" "$REPO/tests/e2e/redeem.sh"
docker build -q -t "$IMAGE" "$REPO/tests/e2e" >/dev/null
ok "images and binaries built"

OWNER_SOCK=/run/grantd/owner/owner.sock

# Everything below drives the system the way a user does, with no grantd
# client binary. The owner mints over a Unix socket with curl, and the visitor
# redeems with install/redeem.sh. If the protocol stops being usable that way,
# these tests fail.

# ---------------------------------------------------------------------- boot

step "starting host and visitor"
docker rm -f "$CONTAINER" "$VISITOR" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null

# The host advertises its own name on the shared network, and the visitor is
# a separate container that resolves it. "Direct SSH, never proxied" is then a
# real property of the test, not a loopback shortcut.
HOST_IP="$CONTAINER"
docker run -d --name "$CONTAINER" --network "$NET" -p "$SSH_PORT:22" \
  -e GRANTD_ORIGIN="$ORIGIN" \
  -e GRANTD_PUBLIC_ORIGIN="$PUBLIC_ORIGIN" \
  -e GRANTD_ADVERTISE_HOST="$CONTAINER" \
  -e GRANTD_ADVERTISE_PORT=22 \
  --add-host=host.docker.internal:host-gateway "$IMAGE" >/dev/null

docker run -d --name "$VISITOR" --network "$NET" --entrypoint sleep \
  --add-host=host.docker.internal:host-gateway "$IMAGE" 3600 >/dev/null
docker exec "$VISITOR" mkdir -p /out

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

# Mint a capability with curl over the owner socket, exactly as documented.
mint() { # mint TTL_SECONDS
  docker exec -u ubuntu "$CONTAINER" sh -c \
    "curl -s --unix-socket $OWNER_SOCK -X POST http://localhost/grants \
       -H 'content-type: application/json' -d '{\"ttl_seconds\":$1}'" \
  | sed -n 's/.*\"capability_url\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p'
}

# Redeem from a separate container, so the visitor is a different machine
# with nothing but curl, openssl and ssh-keygen.
redeem() { # redeem OUTDIR_NAME CAPABILITY_URL  (writes /out/NAME in the visitor)
  docker exec "$VISITOR" sh -c \
    "GRANTD_IDENTITY=/out/$1/identity.pem sh /usr/local/bin/redeem.sh --out /out/$1 '$2'"
}

step "the shell implementation agrees with the frozen vectors"
# The third independent implementation of the canonical encoding. It is
# checked against protocol/test-vectors the same way Go and TypeScript are.
docker cp "$REPO/protocol/test-vectors/v1.json" "$VISITOR:/tmp/v1.json" >/dev/null
if docker exec "$VISITOR" sh /usr/local/bin/cbe-vectors.sh \
     /usr/local/bin/redeem.sh /tmp/v1.json; then
  PASS=$((PASS + 4))
else
  bad "the shell implementation disagrees with the frozen test vectors"
fi

# ---------------------------------------------------- the thing it promises

step "a capability URL becomes an SSH session"
URL="$(mint 1200)"
sleep 3
redeem visit "$URL" > "$WORK/result.json" 2>"$WORK/redeem.err" \
  && ok "redeemed with curl, openssl and ssh-keygen only" \
  || { bad "redeem failed"; tail -5 "$WORK/redeem.err"; }

SSH_OUT=$(docker exec "$VISITOR" ssh -i /out/visit/id_ed25519 \
  -o CertificateFile=/out/visit/id_ed25519-cert.pub \
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR -o ConnectTimeout=10 -p 22 ubuntu@"$HOST_IP" 'whoami' 2>&1)
[ "$SSH_OUT" = "ubuntu" ] && ok "logged in as ubuntu over real sshd" || bad "ssh login: $SSH_OUT"

CERT=/out/visit/id_ed25519-cert.pub
# The serial in the response must be the serial in the certificate. A JSON
# round trip through float64 silently breaks this.
REPORTED=$(sed -n 's/.*"serial"[[:space:]]*:[[:space:]]*"\([0-9]*\)".*/\1/p' "$WORK/result.json")
ACTUAL=$(docker exec "$VISITOR" ssh-keygen -L -f "$CERT" | awk '/Serial:/{print $2}')
[ "$REPORTED" = "$ACTUAL" ] && ok "reported serial matches the certificate ($ACTUAL)" \
  || bad "serial mismatch: reported $REPORTED, certificate $ACTUAL"

PRINCIPALS=$(docker exec "$VISITOR" ssh-keygen -L -f "$CERT" | awk '/Principals:/{getline; print $1}')
[ "$PRINCIPALS" = "ubuntu" ] && ok "certificate carries exactly the enrolled principal" \
  || bad "principals were $PRINCIPALS"

if docker exec "$VISITOR" ssh-keygen -L -f "$CERT" | grep -qE 'permit-(port|agent|X11)-forwarding'; then
  bad "certificate grants forwarding"
else
  ok "certificate grants no port, agent or X11 forwarding"
fi

# ---------------------------------------------------------------- single use

step "a grant is single use"
if redeem visit2 "$URL" >"$WORK/e2" 2>&1; then
  bad "a second agent redeemed an already-used grant"
else
  grep -q GRANT_ALREADY_REDEEMED "$WORK/e2" \
    && ok "second redemption rejected with GRANT_ALREADY_REDEEMED" \
    || bad "second redemption failed with the wrong error: $(tail -2 "$WORK/e2")"
fi

step "there is no retry path"
URL2="$(mint 1200)"; sleep 3
redeem visit3 "$URL2" >/dev/null 2>&1 || true
# The grant is spent. A lost response costs a new capability, not a special
# case in the claim transaction.
if redeem visit3 "$URL2" >"$WORK/e3" 2>&1; then
  bad "a spent grant was redeemed again"
else
  ok "a spent grant cannot be redeemed again"
fi

# ---------------------------------------------------------------- revocation

step "revocation takes effect immediately"
URL3="$(mint 1200)"; sleep 3
GID=$(echo "${URL3%%#*}" | awk -F/ '{print $NF}')
docker exec -u ubuntu "$CONTAINER" sh -c \
  "curl -s -X DELETE --unix-socket $OWNER_SOCK http://localhost/grants/$GID" >/dev/null
if redeem visit4 "$URL3" >"$WORK/e4" 2>&1; then
  bad "a revoked grant was redeemed"
else
  grep -q GRANT_REVOKED "$WORK/e4" && ok "revoked grant rejected with GRANT_REVOKED" \
    || bad "unexpected error: $(tail -2 "$WORK/e4")"
fi

# ------------------------------------------------- local privilege boundary

step "the network-facing daemon cannot reach key material"
# Assume the daemon is fully compromised: run as its uid and try everything.
#
# These assert on exit status, not on error text. A test that greps for
# "permission denied" passes for the wrong reason when the command is
# truncated, silenced, or fails differently.
denied() { # denied DESCRIPTION SHELL_COMMAND
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

# The daemon socket exists for the daemon and is narrow: the grant-creation
# route is not mounted on it.
out=$(docker exec -u grantd "$CONTAINER" sh -c \
  "curl -s -o /dev/null -w '%{http_code}' --unix-socket /run/grantd/redeem/redeem.sock http://localhost/grants" 2>&1)
[ "$out" = "404" ] && ok "daemon socket exposes no grant-creation endpoint" \
  || bad "unexpected status from daemon socket /grants: $out"

# It is reachable, so the 404 above means "no such route", not "no socket".
out=$(docker exec -u grantd "$CONTAINER" sh -c \
  "curl -s -o /dev/null -w '%{http_code}' --unix-socket /run/grantd/redeem/redeem.sock http://localhost/status" 2>&1)
[ "$out" = "200" ] && ok "daemon socket is reachable by the daemon (so the 404 is a missing route)" \
  || bad "daemon could not reach its own socket: $out"

# -------------------------------------------------------------------- expiry

step "expiry is enforced by the host"
URL4="$(mint 60)"; sleep 3
echo "  waiting 65s for the grant to expire..."
sleep 65
if redeem visit5 "$URL4" >"$WORK/e5" 2>&1; then
  bad "an expired grant was redeemed"
else
  grep -qE 'GRANT_EXPIRED' "$WORK/e5" && ok "expired grant rejected with GRANT_EXPIRED" \
    || bad "unexpected error: $(tail -2 "$WORK/e5")"
fi

# ------------------------------------------------------------------- summary

step "summary"
printf '  %d passed, %d failed\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
