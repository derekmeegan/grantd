#!/usr/bin/env bash
#
# Installer test, under real systemd.
#
# The worst failure grantd can have is leaving a remote machine without working
# SSH. These tests are mostly about that: that the installer refuses to reload a
# broken sshd, that it puts back what it found when anything goes wrong, that an
# SSH session open across the install survives it, and that uninstall removes
# the trust path cleanly.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTAINER=grantd-install-test
IMAGE=grantd-install-test
ORIGIN="${GRANTD_TEST_ORIGIN:-https://grantd.derekmeegan.workers.dev}"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
dex()  { docker exec "$CONTAINER" "$@"; }
dsh()  { docker exec "$CONTAINER" bash -c "$1"; }
# As the enrolled owner. Running these as root fails, correctly: root is not in
# the owner's group and cannot traverse the setgid socket directory.
duser(){ docker exec -u ubuntu "$CONTAINER" sh -c "$1"; }

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

step "building linux binaries"
ARCH="$(docker version --format '{{.Server.Arch}}')"
STAGE="$REPO/tests/install/stage"
rm -rf "$STAGE"; mkdir -p "$STAGE"
( cd "$REPO/go"
  export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
  for c in grantd grant-signer; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags "-s -w" -o "$STAGE/$c" "./cmd/$c"
  done )
ok "binaries built for linux/$ARCH"

# Build the image here rather than relying on one built earlier: a stale image
# silently drops tools the tests need.
docker build -q -t "$IMAGE" "$REPO/tests/install" >/dev/null

step "booting a systemd machine"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v "$REPO/install:/opt/grantd-install:ro" \
  -v "$STAGE:/opt/grantd-bin:ro" \
  -p 2223:22 "$IMAGE" >/dev/null

for _ in $(seq 1 60); do
  if dsh 'systemctl is-system-running 2>/dev/null | grep -qE "running|degraded"'; then break; fi
  sleep 1
done
dsh 'systemctl is-system-running || true' >/dev/null
ok "systemd is up"

dsh 'systemctl is-active ssh >/dev/null' && ok "sshd running before install" || bad "sshd not running before install"

# A session held open across the whole install, to prove the reload does not
# disturb established connections.
step "opening an SSH session that must survive the install"
dsh 'mkdir -p /home/ubuntu/.ssh && chmod 700 /home/ubuntu/.ssh && chown ubuntu:ubuntu /home/ubuntu/.ssh'
dsh 'ssh-keygen -q -t ed25519 -N "" -f /root/probe -C probe'
dsh 'cat /root/probe.pub > /home/ubuntu/.ssh/authorized_keys && chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys && chmod 600 /home/ubuntu/.ssh/authorized_keys'
dsh 'nohup ssh -i /root/probe -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR ubuntu@127.0.0.1 "sleep 600; echo done" > /root/held.log 2>&1 &
     sleep 3'
HELD_BEFORE=$(dsh 'pgrep -c -f "sleep 600" || echo 0' | tr -d '[:space:]')
[ "$HELD_BEFORE" -ge 1 ] && ok "a long-lived SSH session is established" || bad "could not establish the held session"

# ---------------------------------------------------------- refuses bad config

step "the installer refuses to reload a broken sshd configuration"
# Break sshd_config in a way that only shows up at validation time, and confirm
# the installer notices before doing anything irreversible.
dsh 'cp /etc/ssh/sshd_config /root/sshd_config.orig && echo "ThisDirectiveDoesNotExist yes" >> /etc/ssh/sshd_config'
if dsh "/opt/grantd-install/install.sh --yes --origin $ORIGIN --ssh-user ubuntu --hostname 127.0.0.1 --port 2223 --local-dir /opt/grantd-bin" >/tmp/broken.log 2>&1; then
  bad "installer ran to completion on a machine whose sshd config was already broken"
else
  grep -q "already fails" /tmp/broken.log \
    && ok "installer stopped, and said the config was broken before it started" \
    || { bad "installer failed for the wrong reason"; tail -5 /tmp/broken.log; }
fi
dsh 'test ! -f /etc/ssh/sshd_config.d/60-grantd.conf' \
  && ok "no grantd snippet was left behind" || bad "a snippet was left behind"
dsh 'cp /root/sshd_config.orig /etc/ssh/sshd_config'
dsh 'sshd -t' && ok "sshd config restored to a valid state" || bad "sshd config still broken"

# ---------------------------------------------------------------- real install

step "installing"
if dsh "/opt/grantd-install/install.sh --yes --origin $ORIGIN --ssh-user ubuntu --hostname 127.0.0.1 --port 2223 --local-dir /opt/grantd-bin" >/tmp/install.log 2>&1; then
  ok "installer completed"
else
  bad "installer failed"; tail -25 /tmp/install.log
fi
HOST_ID=$(grep -o 'h_[a-z2-7]\{32\}' /tmp/install.log | head -1)
[ -n "$HOST_ID" ] && ok "enrolled as $HOST_ID" || bad "no host id in the installer output"

dsh 'sshd -t' && ok "sshd -t passes after install" || bad "sshd -t fails after install"
dsh 'systemctl is-active ssh >/dev/null' && ok "sshd still running" || bad "sshd stopped"

HELD_AFTER=$(dsh 'pgrep -c -f "sleep 600" || echo 0' | tr -d '[:space:]')
[ "$HELD_AFTER" -ge 1 ] \
  && ok "the SSH session opened before the install is still alive" \
  || bad "installing grantd killed an established SSH session"

dsh 'systemctl is-active grant-signer.service >/dev/null' && ok "grant-signer.service active" || bad "grant-signer.service inactive"
dsh 'systemctl is-active grantd.service >/dev/null' && ok "grantd.service active" || bad "grantd.service inactive"

step "permissions after install"
check_mode() { # check_mode <path> <expected> <description>
  actual=$(dsh "stat -c '%a %U:%G' $1" 2>/dev/null | tr -d '\n')
  [ "$actual" = "$2" ] && ok "$3 ($actual)" || bad "$3: got '$actual', want '$2'"
}
check_mode /etc/grantd                 "700 grantsigner:grantsigner" "key directory is private to the signer"
check_mode /etc/grantd/ssh_ca          "600 grantsigner:grantsigner" "SSH CA private key is 0600"
check_mode /etc/grantd/host_identity   "600 grantsigner:grantsigner" "host identity key is 0600"
check_mode /var/lib/grant-signer       "700 grantsigner:grantsigner" "state directory is private"
check_mode /run/grantd/owner           "2770 grantsigner:ubuntu"     "owner socket directory is setgid to the owner"
check_mode /run/grantd/redeem          "2770 grantsigner:grantd"     "daemon socket directory is setgid to the daemon"
check_mode /etc/ssh/grantd_user_ca.pub "644 root:root"               "CA public key is world readable"

step "the systemd sandbox holds"
# The signer is confined to a network namespace with loopback only. This is the
# strongest available statement of "the trust root has no network".
if dsh 'systemctl show grant-signer.service -p PrivateNetwork --value | grep -q yes'; then
  ok "signer unit declares PrivateNetwork=yes"
else
  bad "signer unit is not network-isolated"
fi
if dsh 'systemctl show grantd.service -p InaccessiblePaths --value | grep -q /etc/grantd'; then
  ok "daemon unit makes /etc/grantd inaccessible"
else
  bad "daemon unit does not hide /etc/grantd"
fi
SIGNER_PID=$(dsh 'systemctl show grant-signer.service -p MainPID --value' | tr -d '[:space:]')
if [ -n "$SIGNER_PID" ] && [ "$SIGNER_PID" != "0" ]; then
  if dsh "nsenter -t $SIGNER_PID -n ip -o addr show 2>/dev/null | grep -qv lo" ; then
    bad "the signer's network namespace has an interface other than loopback"
  else
    ok "the signer's network namespace really contains only loopback"
  fi
fi

step "end to end through the installed system"
# Exactly the commands the installer prints, with no grantd client binary
# involved: curl over the owner socket to mint, and install/redeem.sh — curl,
# openssl, ssh-keygen — to redeem. If the documented path ever stops working,
# this fails rather than the documentation quietly becoming wrong.
URL=$(duser "curl -s --unix-socket /run/grantd/owner/owner.sock \
             -X POST http://localhost/grants -H 'content-type: application/json' \
             -d '{\"ttl_seconds\":600}' \
           | sed -n 's/.*\"capability_url\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p'" || true)
case "$URL" in
  http*) ok "ubuntu can mint a capability with curl over the owner socket" ;;
  *) bad "minting failed: $URL" ;;
esac

if [ -n "$URL" ]; then
  sleep 4
  duser "GRANTD_IDENTITY=/tmp/visit/id.pem sh /opt/grantd-install/redeem.sh --out /tmp/visit '$URL'" \
    >/tmp/redeem.log 2>&1 \
    && ok "redeemed with curl, openssl and ssh-keygen only" \
    || { bad "redeem failed"; tail -5 /tmp/redeem.log; }
  OUT=$(duser 'ssh -i /tmp/visit/id_ed25519 -o CertificateFile=/tmp/visit/id_ed25519-cert.pub \
        -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR ubuntu@127.0.0.1 whoami' 2>&1 | tr -d '[:space:]')
  [ "$OUT" = "ubuntu" ] && ok "SSH login with the issued certificate" || bad "ssh failed: $OUT"
fi

# ------------------------------------------------------------------ uninstall

step "uninstalling"
dsh 'cp /tmp/visit/id_ed25519 /root/leftover_key && cp /tmp/visit/id_ed25519-cert.pub /root/leftover_cert.pub && chmod 600 /root/leftover_key' 2>/dev/null || true
if dsh '/opt/grantd-install/uninstall.sh --yes' >/tmp/uninstall.log 2>&1; then
  ok "uninstaller completed"
else
  bad "uninstaller failed"; tail -20 /tmp/uninstall.log
fi

dsh 'sshd -t' && ok "sshd -t passes after uninstall" || bad "sshd -t fails after uninstall"
dsh 'systemctl is-active ssh >/dev/null' && ok "sshd still running after uninstall" || bad "sshd stopped"
dsh 'test ! -e /etc/ssh/sshd_config.d/60-grantd.conf' && ok "sshd snippet removed" || bad "sshd snippet remains"
dsh 'test ! -e /etc/ssh/grantd_user_ca.pub' && ok "CA public key removed from sshd trust" || bad "CA public key remains"
dsh 'test ! -e /etc/grantd/ssh_ca' && ok "SSH CA private key destroyed" || bad "CA private key remains"
dsh 'test ! -e /etc/grantd/host_identity' && ok "host identity key destroyed" || bad "identity key remains"
dsh 'test ! -e /var/lib/grant-signer/state.db' && ok "grant database destroyed" || bad "state database remains"
dsh 'systemctl is-active grantd.service >/dev/null 2>&1' && bad "grantd.service still active" || ok "grantd.service stopped"

# A certificate issued before the uninstall must stop working, because the trust
# path it depends on is gone.
if dsh 'ssh -i /root/leftover_key -o CertificateFile=/root/leftover_cert.pub \
      -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=5 ubuntu@127.0.0.1 whoami' >/dev/null 2>&1; then
  bad "a certificate issued before uninstall still authenticates"
else
  ok "certificates issued before uninstall no longer authenticate"
fi

step "summary"
printf '  %d passed, %d failed\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
