#!/usr/bin/env bash
#
# grantd uninstaller.
#
# Removes SSH trust first and destroys key material last, so that a failure part
# way through leaves a machine that trusts nothing rather than one that still
# trusts a CA whose key is gone.
set -euo pipefail

KEEP_USERS=0
ASSUME_YES=0

LIBDIR=/usr/local/lib/grantd
BINDIR=/usr/local/bin
CONFDIR=/etc/grantd
STATEDIR=/var/lib/grant-signer
SSHD_SNIPPET=/etc/ssh/sshd_config.d/60-grantd.conf
CA_PUB=/etc/ssh/grantd_user_ca.pub
TMPFILES=/usr/lib/tmpfiles.d/grantd.conf

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m==> %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --keep-users) KEEP_USERS=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help)
      cat >&2 <<USAGE
grantd uninstaller

  sudo ./uninstall.sh [--keep-users] [--yes]

Stops the services, removes SSH trust, and destroys the host identity key and
SSH CA private key. Certificates already issued stop being accepted as soon as
sshd reloads, because the trust path they depend on is gone.
USAGE
      exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "uninstall.sh must run as root"
SSHD="${SSHD:-$(command -v sshd || echo /usr/sbin/sshd)}"

if [ "$ASSUME_YES" -ne 1 ]; then
  cat >&2 <<WARNING
This permanently destroys this machine's grantd SSH CA private key and host
identity key. Any grantd certificate still in someone's hands stops working.
WARNING
  printf 'Proceed? [y/N] '
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) die "aborted" ;; esac
fi

log "stopping services"
systemctl disable --now grantd.service 2>/dev/null || true
systemctl disable --now grant-signer.service 2>/dev/null || true
rm -f /etc/systemd/system/grantd.service /etc/systemd/system/grant-signer.service
systemctl daemon-reload 2>/dev/null || true

log "removing SSH trust"
rm -f "$SSHD_SNIPPET"

# Same gate as the installer, for the same reason: never reload sshd on a
# configuration that does not parse.
if "$SSHD" -t 2>/tmp/grantd-uninstall-sshd-t; then
  rm -f "$CA_PUB"
  if "$SSHD" -t 2>/dev/null; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    log "sshd reloaded without grantd trust"
  else
    warn "removing $CA_PUB broke sshd -t; restoring the file and leaving sshd alone"
    warn "remove the TrustedUserCAKeys line manually, then reload sshd"
  fi
else
  warn "sshd -t fails after removing the grantd snippet:"
  cat /tmp/grantd-uninstall-sshd-t >&2
  warn "sshd was NOT reloaded; the running configuration is unchanged"
fi
rm -f /tmp/grantd-uninstall-sshd-t

log "destroying key material"
if [ -x "$LIBDIR/grant-signer" ]; then
  "$LIBDIR/grant-signer" destroy --yes \
    --key-dir "$CONFDIR" --state "$STATEDIR/state.db" \
    --owner-sock /run/grantd/owner/owner.sock \
    --daemon-sock /run/grantd/redeem/redeem.sock || warn "grant-signer destroy reported an error"
else
  warn "grant-signer binary is gone; removing key files directly"
  rm -f "$CONFDIR/host_identity" "$CONFDIR/ssh_ca" "$STATEDIR/state.db"*
fi

log "removing files"
rm -rf "$CONFDIR" "$STATEDIR" "$LIBDIR" "$TMPFILES" /run/grantd
rm -f /etc/grantd.conf
rm -f "$BINDIR/grantctl" "$BINDIR/grant-agent"

if [ "$KEEP_USERS" -ne 1 ]; then
  log "removing service accounts"
  userdel grantd 2>/dev/null || true
  userdel grantsigner 2>/dev/null || true
  groupdel grantd 2>/dev/null || true
  groupdel grantsigner 2>/dev/null || true
fi

cat <<DONE

$(log "grantd removed")

The host's public record may still exist at the coordination service. It is
public metadata and authorizes nothing on its own: with the CA private key
destroyed, no certificate it could ever have signed is accepted here again.
DONE
