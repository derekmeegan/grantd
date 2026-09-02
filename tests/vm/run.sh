#!/usr/bin/env bash
#
# grantd on a real VM.
#
# Containers cannot test three claims that matter most on a machine you
# cannot walk over to:
#
#   1. Reboot. protocol/v1.md §12 says signer state survives, the daemon
#      reconnects, and unexpired grants stay redeemable.
#   2. The systemd sandbox without --privileged. The units are written for a
#      normal machine, not a privileged container.
#   3. "Do not brick SSH", tested where it costs something. Lima reaches this
#      VM over SSH. If the installer breaks sshd, this script loses the
#      machine exactly as it loses a remote host.
#
# It runs on Ubuntu LTS with a 6.x kernel and OpenSSH 9.x. The containers use
# Debian bookworm.
#
# Usage: tests/vm/run.sh [--keep]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VM=grantd-vm
ORIGIN="${GRANTD_TEST_ORIGIN:-https://grantd.derekmeegan.workers.dev}"
# Pinned rather than tracking latest, so a failure here is unambiguous: it means
# this release broke, not that someone published a new one mid-run. Bump it when
# you cut a release.
VERSION="${GRANTD_TEST_VERSION:-v0.2.0}"
SSH_USER=agentuser
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

vm()  { limactl shell "$VM" -- bash -c "$1"; }
vmq() { limactl shell "$VM" -- bash -c "$1" 2>/dev/null; }
# As the enrolled owner. Lima logs in as a different account, and root cannot
# traverse the setgid socket directory either.
owner() { limactl shell "$VM" -- sudo -u "$SSH_USER" sh -c "$1"; }

command -v limactl >/dev/null || { echo "limactl not found; brew install lima" >&2; exit 1; }
limactl list --format '{{.Name}} {{.Status}}' | grep -q "^$VM Running" \
  || { echo "VM '$VM' is not running; limactl start $VM" >&2; exit 1; }

step "the machine"
vm '. /etc/os-release; printf "  %s  %s  kernel %s\n" "$PRETTY_NAME" "$(uname -m)" "$(uname -r)"'
vm 'printf "  virt: %s   systemd %s\n" "$(systemd-detect-virt)" "$(systemctl --version | head -1 | awk "{print \$2}")"'
[ "$(vmq 'systemd-detect-virt' | tr -d '\r\n')" != "none" ] && ok "running on a real VM, not a container" \
  || bad "systemd-detect-virt says this is not virtualized"

# This machine is not a privileged container, so a sandbox that works here
# works for real.
vm "sudo systemd-run --quiet --pipe --property=PrivateNetwork=yes /bin/true" \
  && ok "systemd can create private network namespaces unprivileged" \
  || bad "PrivateNetwork unavailable"

step "preparing"
vm "sudo useradd -m -s /bin/bash $SSH_USER 2>/dev/null; id $SSH_USER >/dev/null" \
  && ok "enrolled account $SSH_USER exists" || bad "could not create $SSH_USER"
vm 'sudo rm -rf /opt/grantd-install && sudo mkdir -p /opt/grantd-install'
tar -C "$REPO" -cf - install | limactl shell "$VM" -- sudo tar -C /opt -xf - --strip-components=1 --one-top-level=grantd-install 2>/dev/null \
  || { tar -C "$REPO/install" -cf - . | limactl shell "$VM" -- sudo tar -C /opt/grantd-install -xf - ; }
vm 'sudo chmod +x /opt/grantd-install/*.sh; test -x /opt/grantd-install/install.sh' \
  && ok "installer staged" || bad "could not stage the installer"

# ------------------------------------------------------------ SSH must survive

step "SSH must survive the install"
# This script reaches the VM over SSH. If the installer breaks sshd, every
# command after this point fails and the machine is gone.
BEFORE_SSHD="$(vmq 'systemctl show ssh -p ActiveState --value' | tr -d '\r\n')"
[ "$BEFORE_SSHD" = "active" ] && ok "sshd active before install" || bad "sshd not active before install"

step "installing $VERSION from $ORIGIN"
if vm "sudo /opt/grantd-install/install.sh --yes --origin $ORIGIN --version $VERSION \
        --ssh-user $SSH_USER --hostname 127.0.0.1" >/tmp/vm-install.log 2>&1; then
  ok "installed from the published release"
else
  bad "install failed"; tail -20 /tmp/vm-install.log
fi
HOST_ID="$(grep -o 'h_[a-z2-7]\{32\}' /tmp/vm-install.log | head -1)"
[ -n "$HOST_ID" ] && ok "enrolled as $HOST_ID" || bad "no host id in installer output"

# If this returns, sshd survived: the command arrived over SSH.
vm 'true' && ok "SSH still works after the install (this command proves it)" \
  || bad "lost SSH access"
vm 'sudo sshd -t' && ok "sshd -t passes" || bad "sshd -t fails"

step "the sandbox holds on a real kernel"
vm 'systemctl is-active grant-signer.service >/dev/null' && ok "signer active" || bad "signer inactive"
vm 'systemctl is-active grantd.service >/dev/null' && ok "daemon active" || bad "daemon inactive"

SIGNER_PID="$(vmq 'systemctl show grant-signer.service -p MainPID --value' | tr -d '\r\n')"
if [ -n "$SIGNER_PID" ] && [ "$SIGNER_PID" != "0" ]; then
  # Enter the signer's network namespace and look.
  IFACES="$(vmq "sudo nsenter -t $SIGNER_PID -n ip -o link show | awk -F': ' '{print \$2}' | tr '\n' ' '")"
  case "$(echo "$IFACES" | tr -d ' ')" in
    lo) ok "signer's network namespace contains only loopback" ;;
    *)  bad "signer namespace has interfaces: $IFACES" ;;
  esac
  # Prove it cannot reach anything.
  if vmq "sudo nsenter -t $SIGNER_PID -n -- curl -s --max-time 5 -o /dev/null $ORIGIN"; then
    bad "the signer could reach the coordination service"
  else
    ok "signer cannot reach the network even when told to"
  fi
fi

vm 'sudo -u grantd cat /etc/grantd/ssh_ca' >/dev/null 2>&1 \
  && bad "daemon read the CA private key" || ok "daemon cannot read the CA private key"
vm 'sudo -u grantd cat /var/lib/grant-signer/state.db' >/dev/null 2>&1 \
  && bad "daemon read the grant database" || ok "daemon cannot read the grant database"

# --------------------------------------------------------------- the happy path

mint() { # mint TTL_SECONDS
  owner "curl -s --unix-socket /run/grantd/owner/owner.sock -X POST http://localhost/grants \
           -H 'content-type: application/json' -d '{\"ttl_seconds\":$1}'" \
  | sed -n 's/.*"capability_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}
redeem() { # redeem OUTDIR URL
  owner "rm -rf $1 && GRANTD_IDENTITY=$1/id.pem sh /opt/grantd-install/redeem.sh --out $1 '$2'"
}
ssh_as_visitor() { # ssh_as_visitor OUTDIR COMMAND
  owner "ssh -i $1/id_ed25519 -o CertificateFile=$1/id_ed25519-cert.pub \
    -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -o ConnectTimeout=10 $SSH_USER@127.0.0.1 '$2'"
}

step "a capability becomes an SSH session"
URL="$(mint 900)"; sleep 3
case "$URL" in http*) ok "minted a capability" ;; *) bad "mint failed: $URL" ;; esac
if redeem /tmp/v1 "$URL" >/tmp/vm-redeem.log 2>&1; then
  ok "redeemed with curl, openssl and ssh-keygen"
else
  bad "redeem failed"; tail -4 /tmp/vm-redeem.log
fi
OUT="$(ssh_as_visitor /tmp/v1 whoami 2>&1 | tr -d '[:space:]')"
[ "$OUT" = "$SSH_USER" ] && ok "SSH login on a real VM with a real kernel" || bad "ssh failed: $OUT"

# -------------------------------------------------------------------- reboot

step "the machine reboots"
# A grant is minted before the reboot and redeemed after. That tests signer
# state on disk, the socket directories on a fresh tmpfs, the daemon
# reconnecting on its own, and the grant staying good.
SURVIVOR_URL="$(mint 1800)"
case "$SURVIVOR_URL" in http*) ok "minted a grant that must survive a reboot" ;; *) bad "mint failed" ;; esac
sleep 3

CERTS_BEFORE="$(vmq 'sudo sqlite3 /var/lib/grant-signer/state.db "select count(*) from certificates" 2>/dev/null || echo unknown' | tr -d '\r\n')"

vm 'sudo systemctl reboot' >/dev/null 2>&1 || true
echo "  waiting for the VM to go down and come back..."
sleep 10
for _ in $(seq 1 60); do
  vmq 'systemctl is-system-running >/dev/null 2>&1 || true; uptime -s' >/dev/null 2>&1 && break
  sleep 3
done
vm 'uptime -s' >/dev/null 2>&1 && ok "VM came back after reboot" || { bad "VM did not come back"; exit 1; }

vm 'systemctl is-active grant-signer.service >/dev/null' \
  && ok "signer started automatically after reboot" || bad "signer did not start after reboot"
vm 'systemctl is-active grantd.service >/dev/null' \
  && ok "daemon started automatically after reboot" || bad "daemon did not start after reboot"

# /run is a tmpfs. The reboot destroyed these directories, and tmpfiles.d must
# have recreated them with their setgid bits.
MODE="$(vmq "stat -c '%a %U:%G' /run/grantd/owner" | tr -d '\r\n')"
[ "$MODE" = "2770 grantsigner:$SSH_USER" ] \
  && ok "socket directory recreated with the right mode and group ($MODE)" \
  || bad "socket directory after reboot: $MODE"

echo "  waiting for the daemon to reconnect..."
RECONNECTED=0
for _ in $(seq 1 40); do
  if vmq 'sudo journalctl -u grantd.service -b --no-pager | grep -q "rendezvous connected"'; then
    RECONNECTED=1; break
  fi
  sleep 2
done
[ "$RECONNECTED" -eq 1 ] && ok "daemon re-established the rendezvous connection on its own" \
  || bad "daemon never reconnected after reboot"

CERTS_AFTER="$(vmq 'sudo sqlite3 /var/lib/grant-signer/state.db "select count(*) from certificates" 2>/dev/null || echo unknown' | tr -d '\r\n')"
[ "$CERTS_BEFORE" = "$CERTS_AFTER" ] \
  && ok "signer state survived the reboot ($CERTS_AFTER certificates still recorded)" \
  || bad "signer state changed across reboot: $CERTS_BEFORE -> $CERTS_AFTER"

step "a grant minted before the reboot still works after it"
if redeem /tmp/v2 "$SURVIVOR_URL" >/tmp/vm-redeem2.log 2>&1; then
  ok "redeemed a pre-reboot grant"
else
  bad "pre-reboot grant could not be redeemed"; tail -4 /tmp/vm-redeem2.log
fi
OUT="$(ssh_as_visitor /tmp/v2 whoami 2>&1 | tr -d '[:space:]')"
[ "$OUT" = "$SSH_USER" ] && ok "SSH login with a certificate issued after the reboot" \
  || bad "ssh failed after reboot: $OUT"

# ---------------------------------------------------- daemon offline and back

step "the daemon goes offline and comes back"
OFFLINE_URL="$(mint 900)"; sleep 3
vm 'sudo systemctl stop grantd.service'
if redeem /tmp/v3 "$OFFLINE_URL" >/tmp/vm-offline.log 2>&1; then
  bad "redeemed while the host daemon was stopped"
else
  grep -q HOST_OFFLINE /tmp/vm-offline.log \
    && ok "redemption while offline returns HOST_OFFLINE, not a generic error" \
    || { bad "wrong error while offline"; tail -2 /tmp/vm-offline.log; }
fi

vm 'sudo systemctl start grantd.service'
for _ in $(seq 1 30); do
  vmq 'sudo journalctl -u grantd.service --since "-1 min" --no-pager | grep -q "rendezvous connected"' && break
  sleep 2
done
sleep 2
# §12: the grant stays valid while the host is away.
if redeem /tmp/v4 "$OFFLINE_URL" >/tmp/vm-back.log 2>&1; then
  ok "the same grant is still redeemable once the host returns"
else
  bad "grant did not survive the daemon being offline"; tail -3 /tmp/vm-back.log
fi

step "an issued certificate outlives the coordination service"
# §12: if the service is unreachable, existing certificates keep working.
vm "sudo iptables -I OUTPUT -p tcp --dport 443 -j REJECT 2>/dev/null || \
    sudo nft add rule inet filter output tcp dport 443 reject 2>/dev/null || true"
OUT="$(ssh_as_visitor /tmp/v4 'echo still-works' 2>&1 | tr -d '[:space:]')"
[ "$OUT" = "still-works" ] \
  && ok "SSH with an existing certificate works with the service unreachable" \
  || bad "certificate stopped working when the service was unreachable: $OUT"
vm "sudo iptables -D OUTPUT -p tcp --dport 443 -j REJECT 2>/dev/null || true"

# ----------------------------------------------------------------- uninstall

step "uninstalling"
vm 'sudo cp /tmp/v4/id_ed25519 /tmp/keep_key && sudo cp /tmp/v4/id_ed25519-cert.pub /tmp/keep_cert.pub \
    && sudo chown $(id -un) /tmp/keep_key /tmp/keep_cert.pub && sudo chmod 600 /tmp/keep_key' 2>/dev/null || true
vm 'sudo /opt/grantd-install/uninstall.sh --yes' >/tmp/vm-uninstall.log 2>&1 \
  && ok "uninstaller completed" || { bad "uninstall failed"; tail -10 /tmp/vm-uninstall.log; }

vm 'true' && ok "SSH still works after the uninstall" || bad "uninstall broke SSH"
vm 'sudo sshd -t' && ok "sshd -t passes after uninstall" || bad "sshd -t fails after uninstall"
vm 'test ! -e /etc/grantd/ssh_ca' && ok "SSH CA private key destroyed" || bad "CA key remains"
vm "ssh -i /tmp/keep_key -o CertificateFile=/tmp/keep_cert.pub -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
    -o ConnectTimeout=5 -o LogLevel=ERROR $SSH_USER@127.0.0.1 whoami" >/dev/null 2>&1 \
  && bad "a certificate issued before uninstall still authenticates" \
  || ok "certificates issued before uninstall no longer authenticate"

step "summary"
printf '  %d passed, %d failed\n\n' "$PASS" "$FAIL"
# The VM is always left running. Without --keep, say how to remove it.
[ "$KEEP" -eq 1 ] || echo "  (VM left running; 'limactl delete -f $VM' to remove it)"
[ "$FAIL" -eq 0 ]
