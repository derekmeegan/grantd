#!/usr/bin/env bash
#
# grantd on a real remote host, over the real internet.
#
#   tests/remote/run.sh user@host [--visitor user@host] [--local-dir DIR | --version V]
#                       [--ssh-user ACCOUNT] [--origin URL] [--advertise ADDRESS]
#                       [--keep] [--yes]
#
# The other suites put the host and the visitor on the same machine, so the
# SSH connection never leaves the box. Here the host is somewhere else and the
# visitor is either wherever you run this script or, with --visitor, a second
# machine that has nothing but curl, openssl and ssh. That covers:
#
#   * a real network path between visitor and host
#   * the rendezvous WebSocket crossing the internet from behind the host's NAT
#   * a `hostname` in the enrollment record that means something to someone else
#   * an installer failure that costs you the machine
#   * a session that outlives its grant, ended by the host and not by the visitor
#
# --local-dir installs the binaries in DIR (grantd, grant-signer, grant-warden,
# grant-admit) instead of a published release, so the code in a checkout can be
# tested before it is released. Build them for the host's architecture first;
# tests/remote/digitalocean.sh does this for you.
#
# READ THIS BEFORE RUNNING IT
#
# It installs grantd on the target and changes that machine's sshd
# configuration. The installer refuses to start if `sshd -t` already fails,
# gates every reload on `sshd -t`, and restores what it found on any error.
# That behaviour is what this script tests, somewhere it matters. Point it at
# a disposable machine.
#
# It cleans up after itself, including uninstalling grantd, unless it fails
# part way through.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET=""
VISITOR=""
SSH_USER=agentuser
ADVERTISE=""
ORIGIN="${GRANTD_TEST_ORIGIN:-https://api.grantd.dev}"
# Pinned rather than tracking latest, so a failure here is unambiguous: it means
# this release broke, not that someone published a new one mid-run. Bump it when
# you cut a release. --local-dir ignores it.
VERSION="${GRANTD_TEST_VERSION:-v0.6.0}"
LOCAL_DIR=""
ASSUME_YES=0
KEEP=0
USER_CREATED=0

while [ $# -gt 0 ]; do
  case "$1" in
    --visitor) VISITOR="$2"; shift 2 ;;
    --ssh-user) SSH_USER="$2"; shift 2 ;;
    --advertise) ADVERTISE="$2"; shift 2 ;;
    --origin) ORIGIN="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --local-dir) LOCAL_DIR="$2"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//;$d' >&2; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) TARGET="$1"; shift ;;
  esac
done
[ -n "$TARGET" ] || { echo "usage: tests/remote/run.sh user@host [--visitor user@host]" >&2; exit 2; }
if [ -n "$LOCAL_DIR" ]; then
  for b in grantd grant-signer; do
    [ -f "$LOCAL_DIR/$b" ] || { echo "--local-dir $LOCAL_DIR has no $b binary" >&2; exit 2; }
  done
fi

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# Your own connection to the box, kept separate from anything grantd issues.
# If the installer breaks sshd, this is what stops working.
#
# GRANTD_SSH_OPTS points at a target that needs a specific key or config
# (-F somefile, -i somekey, -p someport) without editing this script.
# GRANTD_VISITOR_SSH_OPTS does the same for --visitor, and defaults to the
# host's options.
SSH_OPTS="-o ConnectTimeout=15 -o BatchMode=yes ${GRANTD_SSH_OPTS:-}"
VSSH_OPTS="-o ConnectTimeout=15 -o BatchMode=yes ${GRANTD_VISITOR_SSH_OPTS:-${GRANTD_SSH_OPTS:-}}"
rsh()  { ssh $SSH_OPTS "$TARGET" "$@"; }
rsudo(){ ssh $SSH_OPTS "$TARGET" "sudo bash -c '$1'"; }

# On any uncaught failure, dump what the host's supervisor and sshd saw. The
# droplet is destroyed on exit, so this is the only window to see why a login
# was refused or a session was not contained.
DIAGGED=0
diag() {
  [ "$DIAGGED" -eq 0 ] || return 0
  DIAGGED=1
  [ -n "${TARGET:-}" ] || return 0
  printf '\n\033[1mdiagnostics from the host\033[0m\n' >&2
  rsudo 'systemctl --no-pager --failed 2>/dev/null || true;
         echo "=== grant-warden ==="; journalctl -u grant-warden.service -n 120 --no-pager 2>/dev/null || true;
         echo "=== sshd ==="; journalctl -u ssh -n 100 --no-pager 2>/dev/null || true;
         echo "=== auth.log ==="; tail -n 60 /var/log/auth.log 2>/dev/null || true;
         echo "=== pam.d/sshd tail ==="; tail -n 8 /etc/pam.d/sshd 2>/dev/null || true' >&2 2>&1 || true
}
trap 'diag' ERR

# Everything the visitor does goes through these two, so the same test runs
# with the visitor on this machine or on another one. A command string is
# handed to a shell either way; paths in it are paths on the visitor.
vsh() { # vsh COMMAND
  if [ -n "$VISITOR" ]; then ssh $VSSH_OPTS "$VISITOR" "$1"; else bash -c "$1"; fi
}
vput() { # vput LOCAL_FILE VISITOR_PATH
  if [ -n "$VISITOR" ]; then scp -q $VSSH_OPTS "$1" "$VISITOR:$2"; else cp "$1" "$2"; fi
}

WORK="$(mktemp -d)"
VWORK=""
# The stdin of a held session is a sleep this long. It is unusual on purpose,
# so cleanup can find and kill exactly those. The bracket keeps the pattern
# from matching the shell that is running pkill.
HOLD_STDIN=3607
cleanup() {
  [ -z "$VWORK" ] || vsh "pkill -f 'sleep 360[7]' >/dev/null 2>&1; rm -rf '$VWORK'" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step "target"
rsh true 2>/dev/null || { echo "cannot reach $TARGET over SSH" >&2; exit 1; }
rsh '. /etc/os-release; printf "  %s  %s  kernel %s\n" "$PRETTY_NAME" "$(uname -m)" "$(uname -r)"'
# SSH_CONNECTION is "client_ip client_port server_ip server_port". Field 3 is
# the address this machine reached the host on, which is the address a
# visitor must dial.
REMOTE_ADDR="${ADVERTISE:-$(rsh 'echo $SSH_CONNECTION' 2>/dev/null | awk '{print $3}')}"
[ -n "$REMOTE_ADDR" ] || REMOTE_ADDR="$(echo "$TARGET" | sed 's/.*@//')"
echo "  address visitors will dial: $REMOTE_ADDR"

step "visitor"
if [ -n "$VISITOR" ]; then
  vsh true 2>/dev/null || { echo "cannot reach the visitor $VISITOR over SSH" >&2; exit 1; }
  vsh '. /etc/os-release; printf "  %s  %s  kernel %s\n" "$PRETTY_NAME" "$(uname -m)" "$(uname -r)"'
  VWORK="$(vsh 'mktemp -d' | tr -d '\r\n')"
  echo "  visitor:                    $VISITOR (a separate machine)"
else
  VWORK="$WORK"
  echo "  visitor:                    this machine ($(uname -s) $(uname -m))"
fi
# The whole claim of redeem.sh is that these four are enough.
MISSING="$(vsh 'for t in curl openssl ssh ssh-keygen awk; do command -v $t >/dev/null 2>&1 || printf "%s " $t; done')"
[ -z "$MISSING" ] && ok "visitor has curl, openssl, ssh, ssh-keygen and awk" \
  || { bad "visitor is missing: $MISSING"; exit 1; }
vput "$REPO/install/redeem.sh" "$VWORK/redeem.sh" && ok "redeem.sh staged on the visitor" \
  || { bad "could not stage redeem.sh on the visitor"; exit 1; }
REDEEM="$VWORK/redeem.sh"

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
# Only an account this script creates is deleted at the end.
if rsh "id $SSH_USER >/dev/null 2>&1"; then
  ok "enrolled account $SSH_USER already exists"
else
  rsudo "useradd -m -s /bin/bash $SSH_USER" \
    && { USER_CREATED=1; ok "created enrolled account $SSH_USER"; } \
    || bad "could not create $SSH_USER"
fi
# Staged into the login user's home first, then moved into place with sudo.
# Extracting straight into a root-owned directory as a normal user fails on
# that directory's own timestamps. COPYFILE_DISABLE and --no-xattrs keep macOS
# from shipping resource-fork entries that GNU tar rejects.
STAGE="$WORK/stage"
mkdir -p "$STAGE"
cp "$REPO/install/install.sh" "$REPO/install/uninstall.sh" "$REPO/install/redeem.sh" "$STAGE/"
if [ -n "$LOCAL_DIR" ]; then
  mkdir -p "$STAGE/bin"
  cp "$LOCAL_DIR/grantd" "$LOCAL_DIR/grant-signer" \
     "$LOCAL_DIR/grant-warden" "$LOCAL_DIR/grant-admit" "$STAGE/bin/"
fi
rsh 'rm -rf ~/grantd-install && mkdir -p ~/grantd-install'
( cd "$STAGE" && COPYFILE_DISABLE=1 tar --no-xattrs -cf - . 2>/dev/null ) \
  | rsh 'tar -C ~/grantd-install -xf -'
rsudo 'rm -rf /opt/grantd-install && mv ~'"$(rsh 'echo $USER')"'/grantd-install /opt/grantd-install \
       && chown -R root:root /opt/grantd-install \
       && chmod 755 /opt/grantd-install && chmod +x /opt/grantd-install/*.sh' \
  && ok "installer staged" || bad "could not stage the installer"

# Record the SSH state before any change, so "we did not break it" is checked
# and not assumed.
rsudo 'sshd -t' && ok "sshd -t passes before we touch anything" \
  || { bad "sshd already broken on the target; refusing to continue"; exit 1; }

if [ -n "$LOCAL_DIR" ]; then
  step "installing the checkout's binaries"
  SOURCE="--local-dir /opt/grantd-install/bin"
else
  step "installing $VERSION"
  SOURCE="--version $VERSION"
fi
# --hostname is the address the recipient dials. On every other suite it is
# 127.0.0.1 and means nothing.
if rsudo "/opt/grantd-install/install.sh --yes --origin $ORIGIN $SOURCE \
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
# The certificate bounds new connections. The warden is what contains a session
# while it runs and ends it at the deadline, so it must actually be running.
rsudo 'systemctl is-active --quiet grant-warden.service' && ok "lifetime supervisor is running" \
  || bad "grant-warden.service is not running; sessions would be neither contained nor bounded"
rsudo 'test -S /run/grantd/warden/admit.sock' && ok "the admission socket is present" \
  || bad "the admission socket is missing"
rsudo 'systemctl show -p ActiveState --value grantd.slice | grep -q active' \
  && ok "the visitor containment slice is active" \
  || bad "grantd.slice is not active"

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

# ------------------------------------------------------------------- helpers

# Minted as the owner on the host, which with no --owner-user is root.
mint() { # mint TTL_SECONDS
  rsh "sudo curl -s --unix-socket /run/grantd/owner/owner.sock \
        -X POST http://localhost/grants -H 'content-type: application/json' \
        -d '{\"ttl_seconds\":$1}'" \
    | sed -n 's/.*"capability_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}
revoke() { # revoke CAPABILITY_URL
  local gid; gid="$(echo "${1%%#*}" | awk -F/ '{print $NF}')"
  rsh "sudo curl -s -o /dev/null -X DELETE --unix-socket /run/grantd/owner/owner.sock \
        http://localhost/grants/$gid"
}
# Redeemed on the visitor, with no grantd client installed. Stdout is the
# redemption response; stderr is redeem.sh's own complaint.
redeem() { # redeem NAME CAPABILITY_URL   (writes $VWORK/NAME on the visitor)
  vsh "rm -rf '$VWORK/$1' && GRANTD_IDENTITY='$VWORK/$1/id.pem' sh '$REDEEM' --out '$VWORK/$1' '$2'"
}
# Pinned against the known_hosts redeem.sh wrote, keyed by host id. BatchMode
# makes a missing or wrong pin a failure rather than a prompt.
PIN="-o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o BatchMode=yes"
vssh() { # vssh NAME EXTRA_SSH_OPTIONS COMMAND
  vsh "ssh -i '$VWORK/$1/id_ed25519' -o CertificateFile='$VWORK/$1/id_ed25519-cert.pub' \
        -o IdentitiesOnly=yes -o UserKnownHostsFile='$VWORK/$1/known_hosts' $PIN \
        -o HostKeyAlias=$HOST_ID -o LogLevel=ERROR -o ConnectTimeout=20 $2 \
        -l $SSH_USER -- $GOT_HOST '$3'"
}
# A session held open on the host: a pty running a sleep whose length names
# the session, so the host side can be found again. Stdin is a pipe that stays
# open, as a person's terminal would. The ssh client's pid is recorded; the
# session is over when that process is gone.
hold() { # hold NAME SLEEP_SECONDS
  vsh "sleep $HOLD_STDIN </dev/null 2>/dev/null | ssh -tt -i '$VWORK/$1/id_ed25519' \
        -o CertificateFile='$VWORK/$1/id_ed25519-cert.pub' -o IdentitiesOnly=yes \
        -o UserKnownHostsFile='$VWORK/$1/known_hosts' $PIN -o HostKeyAlias=$HOST_ID \
        -o LogLevel=ERROR -o ConnectTimeout=20 -l $SSH_USER -- $GOT_HOST \
        'echo held-$1; exec sleep $2' > '$VWORK/$1.held' 2>&1 & echo \$! > '$VWORK/$1.pid'"
  for _ in $(seq 1 30); do
    vsh "grep -q held-$1 '$VWORK/$1.held'" 2>/dev/null && return 0
    sleep 1
  done
  return 1
}
held_alive() { # held_alive NAME
  vsh "kill -0 \$(cat '$VWORK/$1.pid') 2>/dev/null"
}
on_host() { # on_host SLEEP_SECONDS: number of processes on the host running that sleep
  rsh "pgrep -u $SSH_USER -f 'sleep $1\$' | wc -l" | tr -d '[:space:]'
}
# hold_escaping opens a session that, before it execs its own sleep, launches
# three detached processes a process-name reaper would miss: one under setsid,
# one under nohup, and one double-forked out of a subshell. All four run
# sleeps tagged 800N so the host can find them. The point is that none of these
# escapes the grant's cgroup, and all die when the grant ends.
hold_escaping() { # hold_escaping NAME
  vsh "sleep $HOLD_STDIN </dev/null 2>/dev/null | ssh -tt -i '$VWORK/$1/id_ed25519' \
        -o CertificateFile='$VWORK/$1/id_ed25519-cert.pub' -o IdentitiesOnly=yes \
        -o UserKnownHostsFile='$VWORK/$1/known_hosts' $PIN -o HostKeyAlias=$HOST_ID \
        -o LogLevel=ERROR -o ConnectTimeout=20 -l $SSH_USER -- $GOT_HOST \
        'setsid sh -c \"exec sleep 8001\" </dev/null >/dev/null 2>&1 & \
         nohup sleep 8002 </dev/null >/dev/null 2>&1 & \
         ( setsid sh -c \"exec sleep 8003\" </dev/null >/dev/null 2>&1 & ) ; \
         echo held-$1; exec sleep 8000' > '$VWORK/$1.held' 2>&1 & echo \$! > '$VWORK/$1.pid'"
  for _ in $(seq 1 30); do
    vsh "grep -q held-$1 '$VWORK/$1.held'" 2>/dev/null && return 0
    sleep 1
  done
  return 1
}
# escapers_alive: how many of the four detached sleeps are running on the host.
escapers_alive() { rsh "pgrep -u $SSH_USER -f 'sleep 800[0-3]' | wc -l" | tr -d '[:space:]'; }
# escapers_loose: prints LOOSE if any escaper is running outside a grant cgroup.
escapers_loose() {
  rsh "for p in \$(pgrep -u $SSH_USER -f 'sleep 800[0-3]' 2>/dev/null); do \
         grep -q 'grantd-' /proc/\$p/cgroup 2>/dev/null || { echo LOOSE; break; }; \
       done" | tr -d '[:space:]'
}

# ----------------------------------------------------------------- the path

step "a capability crosses the internet and becomes a session"
URL="$(mint 900)"
case "$URL" in https://*) ok "minted a capability on the remote host" ;; *) bad "mint failed: $URL"; exit 1 ;; esac
sleep 3

if redeem visit "$URL" > "$WORK/redeem.json" 2> "$WORK/redeem.err"; then
  ok "redeemed on the visitor with curl, openssl and ssh-keygen"
else
  bad "redeem failed"; tail -4 "$WORK/redeem.err"
fi

# The connection details must describe the host, not either of us.
GOT_HOST="$(sed -n 's/.*"hostname"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$WORK/redeem.json")"
[ "$GOT_HOST" = "$REMOTE_ADDR" ] && ok "the certificate points at $GOT_HOST" \
  || bad "certificate points at $GOT_HOST, expected $REMOTE_ADDR"
[ -n "$GOT_HOST" ] || GOT_HOST="$REMOTE_ADDR"

CERT="$VWORK/visit/id_ed25519-cert.pub"
PRINCIPALS="$(vsh "ssh-keygen -L -f '$CERT'" 2>/dev/null | awk '/Principals:/{getline; print $1}')"
[ "$PRINCIPALS" = "$SSH_USER" ] && ok "certificate carries exactly the enrolled principal" \
  || bad "principals were: $PRINCIPALS"
if vsh "ssh-keygen -L -f '$CERT'" 2>/dev/null | grep -qE 'permit-(port|agent|X11)-forwarding'; then
  bad "certificate grants forwarding"
else
  ok "certificate grants no port, agent or X11 forwarding"
fi

step "direct SSH, over the internet, never through Cloudflare"
# Checked before the connection attempt, so an unroutable advertised address
# gives an explanation instead of a timeout. A host behind NAT hits this in
# production too.
if ! vsh "timeout 10 bash -c 'exec 3<>/dev/tcp/$GOT_HOST/22'" 2>/dev/null; then
  bad "the visitor cannot reach $GOT_HOST:22, so the direct-SSH leg cannot be tested"
  echo "     The host enrolled an address the visitor cannot route to." >&2
  echo "     On a real remote host that address is public and this works. Pass" >&2
  echo "     --advertise ADDRESS if the one derived from SSH_CONNECTION is wrong." >&2
else
  SSH_OUT="$(vssh visit "" 'echo "$(whoami)@$(hostname)"' 2>&1 | tr -d '\r')"
  case "$SSH_OUT" in
    "$SSH_USER"@*) ok "logged in across the network as $SSH_OUT" ;;
    *) bad "ssh failed: $SSH_OUT" ;;
  esac
  # A second connection under the same grant must also be admitted and
  # contained. This is where a per-connection correlation bug would first show.
  SSH_OUT2="$(vssh visit "" 'whoami' 2>&1 | tr -d '\r' | tail -1)"
  case "$SSH_OUT2" in
    "$SSH_USER") ok "a second connection under the same grant is admitted" ;;
    *) bad "second connection refused: $SSH_OUT2" ;;
  esac
fi
# Cloudflare routed the grant and is now absent from the path: the host sees
# the visitor's own address on the session, not an edge.
if [ -n "$VISITOR" ]; then
  SEEN="$( { vssh visit "" 'echo $SSH_CONNECTION' 2>/dev/null || true; } | awk '{print $1}')"
  # The address this script reached the visitor on is the visitor's public one.
  VISITOR_ADDR="$( { vsh 'echo $SSH_CONNECTION' 2>/dev/null || true; } | awk '{print $3}')"
  [ -n "$SEEN" ] && [ "$SEEN" = "$VISITOR_ADDR" ] \
    && ok "the host sees the visitor's own address on the session ($SEEN)" \
    || bad "the host sees '$SEEN' on the session; the visitor's address is '$VISITOR_ADDR'"
fi

# The pin has to bite. Substitute a different valid host key and the
# connection must be refused, or the pinning above is decoration.
vsh "ssh-keygen -q -t ed25519 -N '' -f '$VWORK/wrong' >/dev/null 2>&1 </dev/null; \
     printf '%s %s\n' '$HOST_ID' \"\$(cut -d' ' -f1,2 < '$VWORK/wrong.pub')\" > '$VWORK/wrong_known_hosts'"
WRONG_OUT="$(vsh "ssh -i '$VWORK/visit/id_ed25519' -o CertificateFile='$VWORK/visit/id_ed25519-cert.pub' \
  -o IdentitiesOnly=yes -o UserKnownHostsFile='$VWORK/wrong_known_hosts' $PIN \
  -o HostKeyAlias=$HOST_ID -o ConnectTimeout=20 -l $SSH_USER -- $GOT_HOST whoami" 2>&1 || true)"
case "$WRONG_OUT" in
  "$SSH_USER"*) bad "logged in despite a wrong pinned host key: the pin is not enforced" ;;
  *"Host key verification failed"*|*"IDENTIFICATION HAS CHANGED"*|*"host key"*)
    ok "a wrong pinned host key refuses the connection" ;;
  *) bad "unexpected result with a wrong host key: $WRONG_OUT" ;;
esac

step "single use holds across the network"
if redeem visit-again "$URL" >/dev/null 2>"$WORK/second.err"; then
  bad "the grant was redeemed twice"
else
  grep -q GRANT_ALREADY_REDEEMED "$WORK/second.err" \
    && ok "a second redemption is refused with GRANT_ALREADY_REDEEMED" \
    || { bad "wrong error on second redemption"; tail -2 "$WORK/second.err"; }
fi

step "a revoked grant cannot be redeemed"
REVOKED_URL="$(mint 900)"; sleep 3
revoke "$REVOKED_URL"
if redeem revoked "$REVOKED_URL" >/dev/null 2>"$WORK/revoked.err"; then
  bad "a revoked grant was redeemed"
else
  grep -q GRANT_REVOKED "$WORK/revoked.err" && ok "revoked grant rejected with GRANT_REVOKED" \
    || { bad "wrong error on a revoked grant"; tail -2 "$WORK/revoked.err"; }
fi

# ------------------------------------------------------------------ deadline
#
# A certificate's expiry stops new connections. The host's warden is what ends
# a session already open, and the documented bound is the deadline plus a small
# grace. Both ends of that are checked: a session is not ended early, and it is
# ended by the bound. A bystander session under a different
# grant is held open throughout and must survive both terminations, along
# with this script's own root session, which every command here is proof of.

step "a session ends when its grant does"
hold visit 612 && ok "bystander session held open under the 900s grant" \
  || bad "could not hold a bystander session open"

MINTED="$(date +%s)"
SHORT_URL="$(mint 60)"
UNUSED_URL="$(mint 60)"
DEADLINE=$((MINTED + 60))
BOUND=$((DEADLINE + 30))
case "$SHORT_URL" in https://*) ok "minted a 60s grant" ;; *) bad "mint failed: $SHORT_URL" ;; esac
sleep 3
redeem short "$SHORT_URL" >/dev/null 2>"$WORK/short.err" && ok "redeemed the 60s grant" \
  || { bad "redeem failed"; tail -3 "$WORK/short.err"; }
if hold_escaping short; then
  ok "session open under the 60s grant, with detached escapers running"
else
  bad "could not open a session under the 60s grant"
fi
sleep 2
[ "$(escapers_alive)" -ge 4 ] && ok "the host is running the session's four processes" \
  || bad "expected four processes on the host, found $(escapers_alive)"
[ -z "$(escapers_loose)" ] \
  && ok "every process, setsid and nohup and double-forked alike, is in the grant cgroup" \
  || bad "a detached process escaped the grant cgroup"

# Not before the deadline.
while [ "$(date +%s)" -lt $((DEADLINE - 15)) ]; do sleep 2; done
held_alive short && ok "the session is still open 15s before the deadline" \
  || bad "the session was ended before its deadline"

ENDED=""
while [ "$(date +%s)" -le $((BOUND + 30)) ]; do
  if ! held_alive short; then ENDED="$(date +%s)"; break; fi
  sleep 2
done
if [ -z "$ENDED" ]; then
  bad "the session is still open $(( $(date +%s) - DEADLINE ))s after its deadline; the warden did not end it"
  vsh "kill \$(cat '$VWORK/short.pid') 2>/dev/null" || true
elif [ "$ENDED" -le "$BOUND" ]; then
  ok "the host ended the session $((ENDED - DEADLINE))s after the deadline (bound: 30s)"
else
  bad "the host ended the session, but $((ENDED - DEADLINE))s after the deadline (bound: 30s)"
fi
# Every escaper is gone, not just the pty's own sleep: cgroup.kill reaches the
# setsid, nohup, and double-forked processes a name-matching reaper would miss.
sleep 3
[ "$(escapers_alive)" -eq 0 ] && ok "all four processes, detached ones included, are gone from the host" \
  || bad "$(escapers_alive) detached processes survived the deadline"

held_alive visit && ok "the bystander session under the other grant is still open" \
  || bad "the bystander session under an unrelated grant was ended too"

# The same deadline, seen from the redemption side.
if redeem unused "$UNUSED_URL" >/dev/null 2>"$WORK/expired.err"; then
  bad "an expired grant was redeemed"
else
  grep -q GRANT_EXPIRED "$WORK/expired.err" && ok "an expired grant is refused with GRANT_EXPIRED" \
    || { bad "wrong error on an expired grant"; tail -2 "$WORK/expired.err"; }
fi

step "revocation ends a running session"
REV_URL="$(mint 900)"; sleep 3
redeem rev "$REV_URL" >/dev/null 2>"$WORK/rev.err" && ok "redeemed a 900s grant" \
  || { bad "redeem failed"; tail -3 "$WORK/rev.err"; }
hold_escaping rev && ok "session open under it, with detached escapers" || bad "could not open a session under it"
REVOKED_AT="$(date +%s)"
revoke "$REV_URL"
ENDED=""
while [ "$(date +%s)" -le $((REVOKED_AT + 60)) ]; do
  if ! held_alive rev; then ENDED="$(date +%s)"; break; fi
  sleep 2
done
if [ -z "$ENDED" ]; then
  bad "the session is still open 60s after revocation"
  vsh "kill \$(cat '$VWORK/rev.pid') 2>/dev/null" || true
elif [ $((ENDED - REVOKED_AT)) -le 30 ]; then
  ok "revocation ended the session within $((ENDED - REVOKED_AT))s (bound: 30s)"
else
  bad "revocation ended the session, but after $((ENDED - REVOKED_AT))s (bound: 30s)"
fi
sleep 3
[ "$(escapers_alive)" -eq 0 ] && ok "revocation killed every process, detached ones included" \
  || bad "$(escapers_alive) detached processes survived revocation"
held_alive visit && ok "the bystander session is still open" \
  || bad "the bystander session under an unrelated grant was ended by the revocation"

# The bystander has done its job.
vsh "kill \$(cat '$VWORK/visit.pid') 2>/dev/null" || true

# ---------------------------------------------------------------- uninstall

if [ "$KEEP" -eq 1 ]; then
  step "leaving grantd installed (--keep)"
else
  step "uninstalling"
  rsudo '/opt/grantd-install/uninstall.sh --yes' > "$WORK/uninstall.log" 2>&1 \
    && ok "uninstalled" || { bad "uninstall failed"; tail -10 "$WORK/uninstall.log"; }
  rsh true && ok "SSH to the host still works after uninstall" || bad "uninstall broke SSH"
  rsudo 'sshd -t' && ok "sshd -t passes after uninstall" || bad "sshd -t fails after uninstall"
  # Nothing of grantd's may keep running: a timer left armed with its script
  # gone fails every fifteen seconds forever.
  LEFT="$(rsudo 'systemctl list-units --no-legend --plain "grantd*" "grant-signer*" 2>/dev/null | awk "{print \$1}"' | tr '\n' ' ')"
  [ -z "${LEFT// /}" ] && ok "no grantd units are loaded" || bad "units still loaded: $LEFT"
  rsudo 'ls /etc/systemd/system/grantd* /etc/systemd/system/grant-signer* 2>/dev/null' > "$WORK/units" || true
  [ ! -s "$WORK/units" ] && ok "no grantd unit files remain" \
    || bad "unit files left behind: $(tr '\n' ' ' < "$WORK/units")"

  # Still pinned: the uninstall removes the CA, not the host key, so this must
  # fail on the certificate rather than on the pin.
  vssh visit "-o ConnectTimeout=15" true >/dev/null 2>&1 \
    && bad "a certificate issued before uninstall still authenticates" \
    || ok "certificates issued before uninstall no longer authenticate"
  rsudo "rm -rf /opt/grantd-install" >/dev/null 2>&1 || true
  if [ "$USER_CREATED" -eq 1 ]; then
    # logind keeps the account's session scope and systemd --user instance
    # for a few seconds after its last connection closes, and userdel refuses
    # while any process still belongs to it. End the sessions and wait.
    rsudo "loginctl terminate-user $SSH_USER 2>/dev/null; \
           for _ in \$(seq 1 30); do pgrep -u $SSH_USER >/dev/null || exit 0; sleep 1; done; \
           echo still running: >&2; ps -u $SSH_USER -o pid=,comm= >&2; exit 1" \
      || bad "processes belonging to $SSH_USER outlived every session"
    if rsudo "userdel -r $SSH_USER" > "$WORK/userdel.log" 2>&1; then
      ok "removed the account this script created"
    else
      bad "could not remove $SSH_USER: $(tr '\n' ' ' < "$WORK/userdel.log")"
    fi
  fi
fi

step "summary"
printf '  %d passed, %d failed\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
