#!/usr/bin/env bash
#
# Provision two throwaway DigitalOcean droplets, a host and a visitor, run
# tests/remote/run.sh between them, and destroy both.
#
#   DIGITALOCEAN_TOKEN=dop_v1_... tests/remote/digitalocean.sh [--local-dir DIR | --version V]
#                                                              [--origin URL] [--single] [--keep]
#
# The last untested property needs a machine with an address a stranger can
# route to, and nothing in between. Workers accept inbound TCP, but that path
# runs through Spectrum, and the property under test is that Cloudflare is not
# in the path.
#
# The visitor is a second droplet in a different region, so the SSH session
# under test crosses the internet between two machines that have never met,
# neither of which is the one running this script. --single skips it and
# makes this machine the visitor, as the suite ran before.
#
# --local-dir installs those binaries (built for linux/amd64) instead of a
# published release, which is how CI tests a checkout. Without it, the
# release pinned in run.sh is installed.
#
# Everything it creates is tagged and torn down on exit, on failure and on
# Ctrl-C. Each droplet costs about a cent an hour and lives for a few minutes.
# In CI the tag carries the run id, so a runner that dies can still be swept
# by tag afterwards.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOKEN="${DIGITALOCEAN_TOKEN:-${DO_TOKEN:-}}"
REGION="${DO_REGION:-nyc3}"
VISITOR_REGION="${DO_VISITOR_REGION:-sfo3}"
SIZE="${DO_SIZE:-s-1vcpu-1gb}"
IMAGE="${DO_IMAGE:-ubuntu-24-04-x64}"
RUN="${GITHUB_RUN_ID:-$$}"
TAG="grantd-test"
RUN_TAG="grantd-test-run-$RUN"
KEEP=0
SINGLE=0
PASSTHROUGH=()

while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1; PASSTHROUGH+=(--keep); shift ;;
    --single) SINGLE=1; shift ;;
    --local-dir|--version|--origin|--ssh-user) PASSTHROUGH+=("$1" "$2"); shift 2 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//;$d' >&2; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
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
HOST_ID=""
VISITOR_ID=""
KEY_ID=""
HOST_IP=""
VISITOR_IP=""

# Teardown runs on every exit path. A public SSH server left running on
# someone's account because a test failed halfway is worse than no test.
cleanup() {
  local rc=$?
  if [ "$KEEP" -eq 1 ] && [ -n "$HOST_ID" ]; then
    echo
    echo "  --keep: host droplet $HOST_ID left running at ${HOST_IP:-unknown}"
    [ -z "$VISITOR_ID" ] || echo "  --keep: visitor droplet $VISITOR_ID left running at ${VISITOR_IP:-unknown}"
    echo "  destroy them with: curl -X DELETE 'https://api.digitalocean.com/v2/droplets?tag_name=$RUN_TAG' -H \"Authorization: Bearer \$DIGITALOCEAN_TOKEN\""
  else
    for id in $HOST_ID $VISITOR_ID; do
      echo "  destroying droplet $id"
      api DELETE "/droplets/$id" >/dev/null 2>&1 || true
    done
    # By tag as well, in case a create call returned an error after the
    # droplet was made.
    api DELETE "/droplets?tag_name=$RUN_TAG" >/dev/null 2>&1 || true
  fi
  [ -n "$KEY_ID" ] && api DELETE "/account/keys/$KEY_ID" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  exit $rc
}
trap cleanup EXIT INT TERM

step "provisioning"
# A keypair for this run only: uploaded now, deleted on the way out.
ssh-keygen -q -t ed25519 -N '' -C "$RUN_TAG" -f "$WORK/key"
PUB="$(cat "$WORK/key.pub")"
KEY_NAME="$RUN_TAG-$$-$(date +%s)"
KEY_ID="$(api POST /account/keys "$(printf '{"name":"%s","public_key":"%s"}' "$KEY_NAME" "$PUB")" \
          | jqp "d['ssh_key']['id']")"
echo "  ssh key $KEY_ID uploaded"

create() { # create NAME REGION  -> droplet id
  local body
  body="$(printf '{"name":"%s","region":"%s","size":"%s","image":"%s","ssh_keys":[%s],"tags":["%s","%s"],"monitoring":false,"ipv6":false}' \
          "$1" "$2" "$SIZE" "$IMAGE" "$KEY_ID" "$TAG" "$RUN_TAG")"
  api POST /droplets "$body" | jqp "d['droplet']['id']"
}
public_ip() { # public_ip DROPLET_ID
  api GET "/droplets/$1" \
    | jqp "next((n['ip_address'] for n in d['droplet']['networks']['v4'] if n['type']=='public'), '')" 2>/dev/null \
    || echo ''
}

HOST_ID="$(create "grantd-host-$RUN" "$REGION")"
echo "  host droplet $HOST_ID creating ($SIZE, $IMAGE, $REGION)"
if [ "$SINGLE" -eq 0 ]; then
  VISITOR_ID="$(create "grantd-visitor-$RUN" "$VISITOR_REGION")"
  echo "  visitor droplet $VISITOR_ID creating ($SIZE, $IMAGE, $VISITOR_REGION)"
fi

for _ in $(seq 1 60); do
  [ -n "$HOST_IP" ] || HOST_IP="$(public_ip "$HOST_ID")"
  [ -n "$VISITOR_IP" ] || [ -z "$VISITOR_ID" ] || VISITOR_IP="$(public_ip "$VISITOR_ID")"
  if [ -n "$HOST_IP" ] && { [ -z "$VISITOR_ID" ] || [ -n "$VISITOR_IP" ]; }; then break; fi
  sleep 5
done
[ -n "$HOST_IP" ] || { echo "host droplet never got a public address" >&2; exit 1; }
echo "  host:    $HOST_IP"
if [ -n "$VISITOR_ID" ]; then
  [ -n "$VISITOR_IP" ] || { echo "visitor droplet never got a public address" >&2; exit 1; }
  echo "  visitor: $VISITOR_IP"
fi

step "waiting for sshd"
# These reach the droplets as root with the key made above. They are not
# visitors and carry no grantd certificate, so there is nothing to pin yet:
# the host key is published by the installer, later.
SSH_OPTS="-i $WORK/key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes"
wait_ssh() { # wait_ssh IP
  for _ in $(seq 1 60); do
    if ssh $SSH_OPTS "root@$1" true 2>/dev/null; then return 0; fi
    sleep 5
  done
  return 1
}
wait_ssh "$HOST_IP" || { echo "sshd never came up on the host $HOST_IP" >&2; exit 1; }
if [ -n "$VISITOR_IP" ]; then
  wait_ssh "$VISITOR_IP" || { echo "sshd never came up on the visitor $VISITOR_IP" >&2; exit 1; }
fi
for ip in $HOST_IP $VISITOR_IP; do
  ssh $SSH_OPTS "root@$ip" '. /etc/os-release; printf "  %s  %s  %s  kernel %s\n" "$(hostname)" "$PRETTY_NAME" "$(uname -m)" "$(uname -r)"'
done

# cloud-init can still be installing packages. A concurrent apt lock breaks
# the installer's own apt use.
for ip in $HOST_IP $VISITOR_IP; do
  ssh $SSH_OPTS "root@$ip" 'cloud-init status --wait >/dev/null 2>&1 || true'
done
echo "  cloud-init settled"

if [ -n "$VISITOR_IP" ]; then
  step "running the remote suite: host $HOST_IP, visitor $VISITOR_IP"
  # Neither machine is this one. The SSH the test performs is a direct TCP
  # connection from the visitor droplet to the host droplet's public address.
  GRANTD_SSH_OPTS="-i $WORK/key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR" \
    "$REPO/tests/remote/run.sh" "root@$HOST_IP" --visitor "root@$VISITOR_IP" --yes ${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}
else
  step "running the remote suite against $HOST_IP, with this machine as the visitor"
  GRANTD_SSH_OPTS="-i $WORK/key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR" \
    "$REPO/tests/remote/run.sh" "root@$HOST_IP" --yes ${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}
fi
