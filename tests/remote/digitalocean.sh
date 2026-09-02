#!/usr/bin/env bash
#
# Provision a throwaway DigitalOcean droplet, run tests/remote/run.sh against
# it, and destroy it.
#
#   DIGITALOCEAN_TOKEN=dop_v1_... tests/remote/digitalocean.sh
#
# The last untested property needs a machine with an address a stranger can
# route to, and nothing in between. Workers accept inbound TCP, but that path
# runs through Spectrum, and the property under test is that Cloudflare is not
# in the path.
#
# Everything it creates is tagged and torn down on exit, on failure and on
# Ctrl-C. The droplet costs about a cent an hour and lives for a few minutes.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOKEN="${DIGITALOCEAN_TOKEN:-${DO_TOKEN:-}}"
REGION="${DO_REGION:-nyc3}"
SIZE="${DO_SIZE:-s-1vcpu-1gb}"
IMAGE="${DO_IMAGE:-ubuntu-24-04-x64}"
KEEP=0
TAG="grantd-test"

[ $# -eq 0 ] || [ "$1" != "--keep" ] || KEEP=1
[ -n "$TOKEN" ] || { echo "set DIGITALOCEAN_TOKEN" >&2; exit 2; }

api() { # api METHOD PATH [BODY]
  if [ -n "${3:-}" ]; then
    curl -sS -X "$1" "https://api.digitalocean.com/v2$2" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      --max-time 60 -d "$3"
  else
    curl -sS -X "$1" "https://api.digitalocean.com/v2$2" \
      -H "Authorization: Bearer $TOKEN" --max-time 60
  fi
}
jqp() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

WORK="$(mktemp -d)"
DROPLET_ID=""
KEY_ID=""

# Teardown runs on every exit path. A public SSH server left running on
# someone's account because a test failed halfway is worse than no test.
cleanup() {
  local rc=$?
  if [ "$KEEP" -eq 1 ] && [ -n "$DROPLET_ID" ]; then
    echo
    echo "  --keep: droplet $DROPLET_ID left running at ${DROPLET_IP:-unknown}"
    echo "  destroy it with: curl -X DELETE https://api.digitalocean.com/v2/droplets/$DROPLET_ID -H \"Authorization: Bearer \$DIGITALOCEAN_TOKEN\""
  else
    [ -n "$DROPLET_ID" ] && { echo; echo "  destroying droplet $DROPLET_ID"; api DELETE "/droplets/$DROPLET_ID" >/dev/null 2>&1 || true; }
  fi
  [ -n "$KEY_ID" ] && api DELETE "/account/keys/$KEY_ID" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  exit $rc
}
trap cleanup EXIT INT TERM

step "provisioning"
# A keypair for this run only: uploaded now, deleted on the way out.
ssh-keygen -q -t ed25519 -N '' -C "grantd-test-$$" -f "$WORK/key"
PUB="$(cat "$WORK/key.pub")"
KEY_NAME="grantd-test-$$-$(date +%s)"
KEY_ID="$(api POST /account/keys "$(printf '{"name":"%s","public_key":"%s"}' "$KEY_NAME" "$PUB")" \
          | jqp "d['ssh_key']['id']")"
echo "  ssh key $KEY_ID uploaded"

BODY="$(printf '{"name":"grantd-test-%s","region":"%s","size":"%s","image":"%s","ssh_keys":[%s],"tags":["%s"],"monitoring":false,"ipv6":false}' \
        "$$" "$REGION" "$SIZE" "$IMAGE" "$KEY_ID" "$TAG")"
DROPLET_ID="$(api POST /droplets "$BODY" | jqp "d['droplet']['id']")"
echo "  droplet $DROPLET_ID creating ($SIZE, $IMAGE, $REGION)"

DROPLET_IP=""
for _ in $(seq 1 60); do
  DROPLET_IP="$(api GET "/droplets/$DROPLET_ID" \
    | jqp "next((n['ip_address'] for n in d['droplet']['networks']['v4'] if n['type']=='public'), '')" 2>/dev/null || echo '')"
  [ -n "$DROPLET_IP" ] && break
  sleep 5
done
[ -n "$DROPLET_IP" ] || { echo "droplet never got a public address" >&2; exit 1; }
echo "  public address: $DROPLET_IP"

step "waiting for sshd"
SSH_OPTS="-i $WORK/key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes"
READY=0
for _ in $(seq 1 60); do
  if ssh $SSH_OPTS "root@$DROPLET_IP" true 2>/dev/null; then READY=1; break; fi
  sleep 5
done
[ "$READY" -eq 1 ] || { echo "sshd never came up on $DROPLET_IP" >&2; exit 1; }
ssh $SSH_OPTS "root@$DROPLET_IP" '. /etc/os-release; printf "  %s  %s  kernel %s\n" "$PRETTY_NAME" "$(uname -m)" "$(uname -r)"'

# cloud-init can still be installing packages. A concurrent apt lock breaks
# the installer's own apt use.
ssh $SSH_OPTS "root@$DROPLET_IP" 'cloud-init status --wait >/dev/null 2>&1 || true'
echo "  cloud-init settled"

step "running the remote suite against $DROPLET_IP"
# This machine reaches the host only over the public internet. The SSH the
# test performs is a direct TCP connection to that address.
GRANTD_SSH_OPTS="-i $WORK/key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR" \
  "$REPO/tests/remote/run.sh" "root@$DROPLET_IP" --yes
