#!/usr/bin/env bash
#
# Installer test, under real systemd.
#
# The worst failure grantd can have is a remote machine without working SSH.
# These tests check that the installer refuses to reload a broken sshd, that
# it puts back what it found when anything goes wrong, that an SSH session
# open across the install survives it, and that uninstall removes the trust
# path cleanly.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTAINER=grantd-install-test
IMAGE=grantd-install-test
ORIGIN="${GRANTD_TEST_ORIGIN:-https://grantd.derekmeegan.workers.dev}"
INSTALL="/opt/grantd-install/install.sh --yes --origin $ORIGIN --ssh-user ubuntu --hostname 127.0.0.1 --port 2223"
SNIPPET=/etc/ssh/sshd_config.d/60-grantd.conf
CA_PUB=/etc/ssh/grantd_user_ca.pub

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
dsh()  { docker exec "$CONTAINER" bash -c "$1"; }
# As the enrolled owner. Root is not in the owner's group and cannot traverse
# the setgid socket directory, so these commands fail as root.
duser(){ docker exec -u ubuntu "$CONTAINER" sh -c "$1"; }

WORK="$(mktemp -d)"
cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# reload_count: the number of sshd reload events in the container's journal.
reload_count() {
  dsh 'journalctl -u ssh --no-pager -o cat 2>/dev/null | grep -ciE "reload|SIGHUP" || true' | tr -d '[:space:]'
}

# assert_absent PATH DESCRIPTION
assert_absent() {
  dsh "test ! -e '$1'" && ok "$2" || bad "$2 ($1 still exists)"
}

# assert_no_account NAME
assert_no_account() {
  dsh "id '$1' >/dev/null 2>&1" && bad "$1 account left behind" || ok "$1 account removed"
}

# assert_nothing_installed: every artifact the installer creates is gone.
assert_nothing_installed() {
  assert_absent /etc/grantd "key directory removed"
  assert_absent /var/lib/grant-signer "state directory removed"
  assert_absent /usr/local/lib/grantd "binaries removed"
  assert_absent /usr/lib/tmpfiles.d/grantd.conf "tmpfiles configuration removed"
  assert_absent /etc/grantd.conf "public configuration removed"
  assert_absent /etc/systemd/system/grant-signer.service "signer unit removed"
  assert_absent /etc/systemd/system/grantd.service "daemon unit removed"
  assert_absent /run/grantd "runtime directory removed"
  assert_no_account grantd
  assert_no_account grantsigner
}

# assert_held_session_alive: the SSH session opened before the installs is
# still running.
assert_held_session_alive() {
  held="$(dsh 'pgrep -c -f "sleep 600" || echo 0' | tr -d '[:space:]')"
  [ "$held" -ge 1 ] \
    && ok "the SSH session opened before the install is still alive" \
    || bad "an established SSH session was killed"
}

# --------------------------------------------------------------------- build

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

# Build the image every run. A stale image silently drops tools the tests need.
docker build -q -t "$IMAGE" "$REPO/tests/install" >/dev/null

# ---------------------------------------------------------------------- boot

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

# A session held open across every install, to prove that reloads do not
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

# ---------------------------------------------------- refuses a broken config

step "the installer refuses to start on a broken sshd configuration"
# Break sshd_config in a way that only shows up at validation time.
dsh 'cp /etc/ssh/sshd_config /root/sshd_config.orig && echo "ThisDirectiveDoesNotExist yes" >> /etc/ssh/sshd_config'
if dsh "$INSTALL --local-dir /opt/grantd-bin" >/tmp/broken.log 2>&1; then
  bad "installer ran to completion on a machine whose sshd config was already broken"
else
  grep -q "already fails" /tmp/broken.log \
    && ok "installer stopped, and said the config was broken before it started" \
    || { bad "installer failed for the wrong reason"; tail -5 /tmp/broken.log; }
fi
assert_absent "$SNIPPET" "no grantd snippet was left behind"
dsh 'cp /root/sshd_config.orig /etc/ssh/sshd_config'
dsh 'sshd -t' && ok "sshd config restored to a valid state" || bad "sshd config still broken"

# ------------------------------------------------- rollback: enrollment fails

step "the installer undoes everything when enrollment fails"
# A grant-signer that exits 1 at init. Accounts, directories, binaries and
# configuration already exist at that point, and all of it must go.
printf '#!/bin/sh\necho "grant-signer: init failed on purpose" >&2\nexit 1\n' > "$WORK/grant-signer"
chmod 0755 "$WORK/grant-signer"
dsh 'mkdir -p /opt/grantd-bad && cp /opt/grantd-bin/grantd /opt/grantd-bad/grantd'
docker cp "$WORK/grant-signer" "$CONTAINER:/opt/grantd-bad/grant-signer"
RELOADS="$(reload_count)"
if dsh "$INSTALL --local-dir /opt/grantd-bad" >/tmp/enroll-fail.log 2>&1; then
  bad "installer completed with a grant-signer that cannot enroll"
else
  grep -q "enrollment failed" /tmp/enroll-fail.log \
    && ok "installer stopped at enrollment" \
    || { bad "installer failed for the wrong reason"; tail -5 /tmp/enroll-fail.log; }
fi
assert_absent "$SNIPPET" "no sshd snippet left behind"
assert_absent "$CA_PUB" "no CA public key left behind"
assert_nothing_installed
dsh 'sshd -t' && ok "sshd -t passes after the rollback" || bad "sshd -t fails after the rollback"
[ "$(reload_count)" = "$RELOADS" ] \
  && ok "sshd was not reloaded: its configuration never changed" \
  || bad "sshd was reloaded although its configuration never changed"
assert_held_session_alive

# ------------------------------------------- rollback: new config fails sshd -t

step "the installer restores the previous SSH configuration when sshd -t rejects the new one"
# Plant an existing snippet and CA file, so "restored" can be told apart from
# "removed".
dsh "printf '# planted by the test\n' > $SNIPPET && printf 'planted\n' > $CA_PUB"
# A wrapper ahead of the real sshd in PATH. It rejects \`-t\` while the
# installer's own snippet is in place, and passes everything else through.
# The real sshd never sees an invalid configuration.
cat > "$WORK/sshd" <<'WRAPPER'
#!/bin/sh
snippet=/etc/ssh/sshd_config.d/60-grantd.conf
if [ "${1:-}" = "-t" ] && [ -f "$snippet" ] && ! grep -q "planted by the test" "$snippet"; then
  echo "sshd wrapper: rejecting the grantd snippet on purpose" >&2
  exit 1
fi
exec /usr/sbin/sshd "$@"
WRAPPER
chmod 0755 "$WORK/sshd"
docker cp "$WORK/sshd" "$CONTAINER:/usr/local/sbin/sshd"
RELOADS="$(reload_count)"
if dsh "$INSTALL --local-dir /opt/grantd-bin" >/tmp/sshd-fail.log 2>&1; then
  bad "installer completed although sshd -t rejected the new configuration"
else
  grep -q "refusing to reload sshd" /tmp/sshd-fail.log \
    && ok "installer refused to reload sshd" \
    || { bad "installer failed for the wrong reason"; tail -5 /tmp/sshd-fail.log; }
fi
dsh 'rm -f /usr/local/sbin/sshd'
[ "$(dsh "cat $SNIPPET")" = "# planted by the test" ] \
  && ok "the previous sshd snippet was restored" || bad "the previous sshd snippet was not restored"
[ "$(dsh "cat $CA_PUB")" = "planted" ] \
  && ok "the previous CA public key was restored" || bad "the previous CA public key was not restored"
assert_nothing_installed
dsh 'sshd -t' && ok "sshd -t passes on the restored configuration" || bad "sshd -t fails on the restored configuration"
[ "$(reload_count)" -gt "$RELOADS" ] \
  && ok "sshd was reloaded once the previous configuration was back" \
  || bad "sshd was not reloaded after the restore"
assert_held_session_alive
dsh "rm -f $SNIPPET $CA_PUB"

# -------------------------------------------------------------- real install

step "installing"
RELOADS="$(reload_count)"
if dsh "$INSTALL --local-dir /opt/grantd-bin" >/tmp/install.log 2>&1; then
  ok "installer completed"
else
  bad "installer failed"; tail -25 /tmp/install.log
fi
HOST_ID=$(grep -o 'h_[a-z2-7]\{32\}' /tmp/install.log | head -1)
[ -n "$HOST_ID" ] && ok "enrolled as $HOST_ID" || bad "no host id in the installer output"

dsh 'sshd -t' && ok "sshd -t passes after install" || bad "sshd -t fails after install"
dsh 'systemctl is-active ssh >/dev/null' && ok "sshd still running" || bad "sshd stopped"
# This proves the journal records reloads, so the reload assertions above
# cannot pass for the wrong reason.
[ "$(reload_count)" -gt "$RELOADS" ] \
  && ok "the reload is visible in the journal" \
  || bad "the journal shows no reload; the reload assertions above are not trustworthy"
assert_held_session_alive

dsh 'systemctl is-active grant-signer.service >/dev/null' && ok "grant-signer.service active" || bad "grant-signer.service inactive"
dsh 'systemctl is-active grantd.service >/dev/null' && ok "grantd.service active" || bad "grantd.service inactive"

step "permissions after install"
check_mode() { # check_mode PATH EXPECTED DESCRIPTION
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
# The signer is confined to a network namespace with loopback only. Enter the
# namespace and look.
SIGNER_PID=$(dsh 'systemctl show grant-signer.service -p MainPID --value' | tr -d '[:space:]')
if [ -n "$SIGNER_PID" ] && [ "$SIGNER_PID" != "0" ]; then
  if dsh "nsenter -t $SIGNER_PID -n ip -o addr show 2>/dev/null | grep -qv lo" ; then
    bad "the signer's network namespace has an interface other than loopback"
  else
    ok "the signer's network namespace really contains only loopback"
  fi
fi
# The daemon's mount namespace hides the key material from everyone, root
# included. First prove the namespace can be entered, so a failure to read
# cannot pass for the wrong reason.
DAEMON_PID=$(dsh 'systemctl show grantd.service -p MainPID --value' | tr -d '[:space:]')
if [ -n "$DAEMON_PID" ] && [ "$DAEMON_PID" != "0" ] && dsh "nsenter -t $DAEMON_PID -m -- true" >/dev/null 2>&1; then
  if dsh "nsenter -t $DAEMON_PID -m -- test -e /etc/grantd/ssh_ca" >/dev/null 2>&1; then
    bad "inside the daemon's mount namespace, the CA private key is visible"
  else
    ok "inside the daemon's mount namespace, the CA private key does not exist"
  fi
else
  bad "could not enter the daemon's mount namespace"
fi

step "end to end through the installed system"
# Exactly the commands the installer prints, with no grantd client binary.
# If the documented path stops working, this fails.
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
  OUT=$(duser "ssh -i /tmp/visit/id_ed25519 -o CertificateFile=/tmp/visit/id_ed25519-cert.pub \
        -o IdentitiesOnly=yes -o UserKnownHostsFile=/tmp/visit/known_hosts \
        -o StrictHostKeyChecking=yes -o HostKeyAlias=$HOST_ID -o HostKeyAlgorithms=ssh-ed25519 \
        -o BatchMode=yes -o LogLevel=ERROR -l ubuntu -- 127.0.0.1 whoami" 2>&1 | tr -d '[:space:]')
  [ "$OUT" = "ubuntu" ] && ok "SSH login with the issued certificate" || bad "ssh failed: $OUT"
fi

# ----------------------------------------------------------------- uninstall

step "uninstalling"
dsh 'cp /tmp/visit/id_ed25519 /root/leftover_key && cp /tmp/visit/id_ed25519-cert.pub /root/leftover_cert.pub && cp /tmp/visit/known_hosts /root/leftover_known_hosts && chmod 600 /root/leftover_key' 2>/dev/null || true
if dsh '/opt/grantd-install/uninstall.sh --yes' >/tmp/uninstall.log 2>&1; then
  ok "uninstaller completed"
else
  bad "uninstaller failed"; tail -20 /tmp/uninstall.log
fi

dsh 'sshd -t' && ok "sshd -t passes after uninstall" || bad "sshd -t fails after uninstall"
dsh 'systemctl is-active ssh >/dev/null' && ok "sshd still running after uninstall" || bad "sshd stopped"
assert_absent "$SNIPPET" "sshd snippet removed"
assert_absent "$CA_PUB" "CA public key removed from sshd trust"
assert_absent /etc/grantd/ssh_ca "SSH CA private key destroyed"
assert_absent /etc/grantd/host_identity "host identity key destroyed"
assert_absent /var/lib/grant-signer/state.db "grant database destroyed"
dsh 'systemctl is-active grantd.service >/dev/null 2>&1' && bad "grantd.service still active" || ok "grantd.service stopped"

# A certificate issued before the uninstall must stop working. The trust path
# it depends on is gone.
# Still pinned, with the known_hosts from the successful login: the uninstall
# destroys the CA, not the host key, so this must fail on the certificate and
# not on the pin, or it passes for the wrong reason.
if dsh "ssh -i /root/leftover_key -o CertificateFile=/root/leftover_cert.pub \
      -o IdentitiesOnly=yes -o UserKnownHostsFile=/root/leftover_known_hosts \
      -o StrictHostKeyChecking=yes -o HostKeyAlias=$HOST_ID -o HostKeyAlgorithms=ssh-ed25519 \
      -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=5 -l ubuntu -- 127.0.0.1 whoami" >/dev/null 2>&1; then
  bad "a certificate issued before uninstall still authenticates"
else
  ok "certificates issued before uninstall no longer authenticate"
fi

step "summary"
printf '  %d passed, %d failed\n\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
