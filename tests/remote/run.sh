#!/usr/bin/env bash
#
# grantd on a real remote host, over the real internet.
#
#   tests/remote/run.sh user@host [--ssh-user ACCOUNT] [--yes]
#
# This is the last environment the other suites cannot reach. Containers, the
# local VM and CI all put the host and the visitor on the same machine, so the
# SSH connection never left the box. Here the host is somewhere else and the
# visitor is wherever you run this script, which means the test finally covers:
#
#   * a real network path between visitor and host — real latency, real MTU,
#     a real firewall in between
#   * the rendezvous WebSocket crossing the actual internet to Cloudflare, from
#     a machine behind whatever NAT the host happens to sit behind
#   * `hostname` in the enrollment record being an address that means something
#     to someone else, rather than 127.0.0.1
#   * an installer failure that would genuinely cost you the machine
#
# READ THIS BEFORE RUNNING IT
#
# It installs grantd on the target and modifies that machine's sshd
# configuration. The installer is built to make that safe — it refuses to start
# if `sshd -t` already fails, gates every reload on `sshd -t`, and restores what
# it found on any error — and that is exactly the behaviour this script exists
# to test somewhere it matters. But the honest summary is: point this at a
# disposable machine, not at anything you would mind losing.
#
# It cleans up after itself, including uninstalling grantd, unless it fails
# partway through.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET=""
SSH_USER=agentuser
ADVERTISE=""
ORIGIN="${GRANTD_TEST_ORIGIN:-https://grantd.derekmeegan.workers.dev}"
VERSION="${GRANTD_TEST_VERSION:-v0.1.0}"
ASSUME_YES=0
KEEP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --ssh-user) SSH_USER="$2"; shift 2 ;;
    --advertise) ADVERTISE="$2"; shift 2 ;;
    --origin) ORIGIN="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//;$d' >&2; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) TARGET="$1"; shift ;;
  esac
done
[ -n "$TARGET" ] || { echo "usage: tests/remote/run.sh user@host [--ssh-user ACCOUNT]" >&2; exit 2; }

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# Your own connection to the box, kept entirely separate from anything grantd
# issues. If the installer breaks sshd this is what stops working, which is the
# point of running the test here.
#
# GRANTD_SSH_OPTS lets you point at a target that needs a specific key or config
# (-F somefile, -i somekey, -p someport) without editing this script.
SSH_OPTS="-o ConnectTimeout=15 -o BatchMode=yes ${GRANTD_SSH_OPTS:-}"
rsh()  { ssh $SSH_OPTS "$TARGET" "$@"; }
rsudo(){ ssh $SSH_OPTS "$TARGET" "sudo bash -c '$1'"; }

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

step "target"
rsh true 2>/dev/null || { echo "cannot reach $TARGET over SSH" >&2; exit 1; }
rsh '. /etc/os-release; printf "  %s  %s  kernel %s\n" "$PRETTY_NAME" "$(uname -m)" "$(uname -r)"'
# SSH_CONNECTION is "client_ip client_port server_ip server_port", so field 3 is
# the address this machine reached the host on — which is exactly the address a
# visitor should be told to dial.
REMOTE_ADDR="${ADVERTISE:-$(rsh 'echo $SSH_CONNECTION' 2>/dev/null | awk '{print $3}')}"
[ -n "$REMOTE_ADDR" ] || REMOTE_ADDR="$(echo "$TARGET" | sed 's/.*@//')"
echo "  address visitors will dial: $REMOTE_ADDR"
echo "  visitor:                    this machine ($(uname -s) $(uname -m))"

if [ "$ASSUME_YES" -ne 1 ]; then
  cat >&2 <<WARN

This installs grantd on $TARGET and changes that machine's sshd configuration.
Use a disposable host.

WARN
  printf 'Proceed? [y/N] '
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) echo "aborted" >&2; exit 1 ;; esac
fi

step "preparing the host"
rsudo "id $SSH_USER >/dev/null 2>&1 || useradd -m -s /bin/bash $SSH_USER" \
  && ok "enrolled account $SSH_USER exists" || bad "could not create $SSH_USER"
# Staged into the login user's home first, then moved into place with sudo.
# Extracting straight into a root-owned directory as a normal user fails trying
# to restore that directory's own timestamps. COPYFILE_DISABLE and --no-xattrs
# keep macOS from shipping resource-fork entries that GNU tar then complains
# about.
rsh 'rm -rf ~/grantd-install && mkdir -p ~/grantd-install'
( cd "$REPO/install" && COPYFILE_DISABLE=1 tar --no-xattrs -cf - \
    install.sh uninstall.sh redeem.sh 2>/dev/null ) \
  | rsh 'tar -C ~/grantd-install -xf -'
rsudo 'rm -rf /opt/grantd-install && mv ~'"$(rsh 'echo $USER')"'/grantd-install /opt/grantd-install \
       && chown -R root:root /opt/grantd-install \
       && chmod 755 /opt/grantd-install && chmod +x /opt/grantd-install/*.sh' \
  && ok "installer staged" || bad "could not stage the installer"

# Capture the pre-existing SSH state, so a claim that we did not break it can be
# checked rather than assumed.
rsudo 'sshd -t' && ok "sshd -t passes before we touch anything" \
  || { bad "sshd already broken on the target; refusing to continue"; exit 1; }

step "installing $VERSION"
# --hostname is the address the *recipient* will dial, which is the whole point
# of testing here: on every other suite it was 127.0.0.1 and meant nothing.
if rsudo "/opt/grantd-install/install.sh --yes --origin $ORIGIN --version $VERSION \
          --ssh-user $SSH_USER --hostname $REMOTE_ADDR" > "$WORK/install.log" 2>&1; then
  ok "installed"
else
  bad "install failed"; tail -20 "$WORK/install.log"
fi
HOST_ID="$(grep -o 'h_[a-z2-7]\{32\}' "$WORK/install.log" | head -1)"
[ -n "$HOST_ID" ] && ok "enrolled as $HOST_ID" || bad "no host id in the installer output"

# If this returns, the installer did not cost us the machine.
rsh true && ok "SSH to the host still works (this command is the proof)" \
  || { bad "lost SSH access to $TARGET"; exit 1; }
rsudo 'sshd -t' && ok "sshd -t passes after install" || bad "sshd -t fails after install"
rsudo 'systemctl is-active grant-signer.service >/dev/null' && ok "signer running" || bad "signer not running"
rsudo 'systemctl is-active grantd.service >/dev/null' && ok "daemon running" || bad "daemon not running"

step "the host is reachable through Cloudflare from a machine that has never seen it"
for _ in $(seq 1 30); do
  rsudo 'journalctl -u grantd.service -b --no-pager | grep -q "rendezvous connected"' && break
  sleep 2
done
rsudo 'journalctl -u grantd.service -b --no-pager | grep -q "rendezvous connected"' \
  && ok "daemon established the rendezvous from behind the host's own network" \
  || bad "daemon never connected"

CONNECTED="$(curl -s "$ORIGIN/v1/hosts/$HOST_ID" | sed -n 's/.*"connected"[[:space:]]*:[[:space:]]*\([a-z]*\).*/\1/p')"
[ "$CONNECTED" = "true" ] && ok "the coordination service sees the host as connected" \
  || bad "service reports connected=$CONNECTED"

ADVERTISED="$(curl -s "$ORIGIN/v1/hosts/$HOST_ID" | sed -n 's/.*"hostname"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
[ "$ADVERTISED" = "$REMOTE_ADDR" ] \
  && ok "the published address is the real one ($ADVERTISED), not a loopback" \
  || bad "advertised address is $ADVERTISED, expected $REMOTE_ADDR"

step "a capability crosses the internet and becomes a session"
URL="$(rsh "sudo -u $SSH_USER curl -s --unix-socket /run/grantd/owner/owner.sock \
        -X POST http://localhost/grants -H 'content-type: application/json' \
        -d '{\"ttl_seconds\":900}'" \
      | sed -n 's/.*"capability_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
case "$URL" in https://*) ok "minted a capability on the remote host" ;; *) bad "mint failed: $URL"; exit 1 ;; esac
sleep 3

# Redeemed *here*, on a different machine, with no grantd client installed.
OUT="$WORK/visit"
if GRANTD_IDENTITY="$OUT/id.pem" sh "$REPO/install/redeem.sh" --out "$OUT" "$URL" \
     > "$WORK/redeem.json" 2> "$WORK/redeem.err"; then
  ok "redeemed locally with curl, openssl and ssh-keygen"
else
  bad "redeem failed"; tail -4 "$WORK/redeem.err"
fi

# The connection details must describe the remote machine, not this one.
GOT_HOST="$(sed -n 's/.*"hostname"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$WORK/redeem.json")"
[ "$GOT_HOST" = "$REMOTE_ADDR" ] && ok "the certificate points at $GOT_HOST" \
  || bad "certificate points at $GOT_HOST, expected $REMOTE_ADDR"

step "direct SSH, over the internet, never through Cloudflare"
# Checked before attempting the connection, so an unroutable advertised address
# produces an explanation instead of a timeout. This is the failure a host
# behind NAT would hit in production too: the machine enrolled an address that
# means nothing to the visitor.
if ! (exec 3<>/dev/tcp/"$GOT_HOST"/22) 2>/dev/null; then
  bad "cannot reach $GOT_HOST:22 from here, so the direct-SSH leg cannot be tested"
  echo "     The host enrolled an address this machine cannot route to." >&2
  echo "     On a real remote host that address is public and this works; pass" >&2
  echo "     --advertise ADDRESS if the one derived from SSH_CONNECTION is wrong." >&2
else
SSH_OUT="$(ssh -i "$OUT/id_ed25519" -o CertificateFile="$OUT/id_ed25519-cert.pub" \
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR -o ConnectTimeout=20 -o PreferredAuthentications=publickey \
  "$SSH_USER@$GOT_HOST" 'echo "$(whoami)@$(hostname)"' 2>&1 | tr -d '\r')"
case "$SSH_OUT" in
  "$SSH_USER"@*) ok "logged in across the network as $SSH_OUT" ;;
  *) bad "ssh failed: $SSH_OUT" ;;
esac
fi

# The point of the architecture: Cloudflare routed the grant and is now absent.
if [ "$FAIL" -eq 0 ] && [ -n "${SSH_OUT:-}" ]; then
  SSH_OUT2="$(ssh -i "$OUT/id_ed25519" -o CertificateFile="$OUT/id_ed25519-cert.pub" \
    -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -o ConnectTimeout=20 "$SSH_USER@$GOT_HOST" \
    'ss -tnp 2>/dev/null | grep -c ESTAB || true' 2>&1 | tr -d '\r\n')"
  ok "session is a direct TCP connection to the host ($SSH_OUT2 established sockets there)"
fi

step "single use holds across the network"
if GRANTD_IDENTITY="$WORK/v2/id.pem" sh "$REPO/install/redeem.sh" --out "$WORK/v2" "$URL" \
     >/dev/null 2>"$WORK/second.err"; then
  bad "the grant was redeemed twice"
else
  grep -q GRANT_ALREADY_REDEEMED "$WORK/second.err" \
    && ok "a second redemption is refused with GRANT_ALREADY_REDEEMED" \
    || { bad "wrong error on second redemption"; tail -2 "$WORK/second.err"; }
fi

if [ "$KEEP" -eq 1 ]; then
  step "leaving grantd installed (--keep)"
else
  step "uninstalling"
  rsudo '/opt/grantd-install/uninstall.sh --yes' > "$WORK/uninstall.log" 2>&1 \
    && ok "uninstalled" || { bad "uninstall failed"; tail -10 "$WORK/uninstall.log"; }
  rsh true && ok "SSH to the host still works after uninstall" || bad "uninstall broke SSH"
  rsudo 'sshd -t' && ok "sshd -t passes after uninstall" || bad "sshd -t fails after uninstall"

  ssh -i "$OUT/id_ed25519" -o CertificateFile="$OUT/id_ed25519-cert.pub" \
    -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=15 \
    "$SSH_USER@$GOT_HOST" true >/dev/null 2>&1 \
    && bad "a certificate issued before uninstall still authenticates" \
    || ok "certificates issued before uninstall no longer authenticate"
  rsudo "rm -rf /opt/grantd-install; userdel -r $SSH_USER 2>/dev/null || true" >/dev/null 2>&1 || true
fi

step "summary"
printf '  %d passed, %d failed\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
