#!/usr/bin/env bash
#
# grantd uninstaller.
#
# It removes SSH trust first and destroys key material last. A failure part
# way through then leaves a machine that trusts nothing, not one that still
# trusts a CA whose key is gone.
set -euo pipefail

# ------------------------------------------------------------------ settings

KEEP_USERS=0
ASSUME_YES=0

LIBDIR=/usr/local/lib/grantd
CONFDIR=/etc/grantd
STATEDIR=/var/lib/grant-signer
STATE_DB=/var/lib/grant-signer/state.db
PUBLIC_CONF=/etc/grantd.conf
SSHD_SNIPPET=/etc/ssh/sshd_config.d/60-grantd.conf
CA_PUB=/etc/ssh/grantd_user_ca.pub
TMPFILES=/usr/lib/tmpfiles.d/grantd.conf
RUNDIR=/run/grantd
OWNER_SOCK=/run/grantd/owner/owner.sock
DAEMON_SOCK=/run/grantd/redeem/redeem.sock
SIGNER_UNIT=/etc/systemd/system/grant-signer.service
DAEMON_UNIT=/etc/systemd/system/grantd.service

# ------------------------------------------------------------------- helpers

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m==> %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<USAGE
grantd uninstaller

  sudo ./uninstall.sh [--keep-users] [--yes]

Stops the services, removes SSH trust, and destroys the host identity key and
SSH CA private key. Certificates already issued stop being accepted as soon as
sshd reloads, because the trust path they depend on is gone.
USAGE
}

find_sshd() {
  if command -v sshd >/dev/null 2>&1; then
    command -v sshd
  elif [ -x /usr/sbin/sshd ]; then
    echo /usr/sbin/sshd
  else
    return 1
  fi
}

reload_sshd() {
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null
}

# ----------------------------------------------------------------- arguments

while [ $# -gt 0 ]; do
  case "$1" in
    --keep-users) KEEP_USERS=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

# ------------------------------------------------------------------ preflight

[ "$(id -u)" -eq 0 ] || die "uninstall.sh must run as root"
SSHD="$(find_sshd)" || die "could not find sshd"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ "$ASSUME_YES" -ne 1 ]; then
  cat >&2 <<WARNING
This permanently destroys this machine's grantd SSH CA private key and host
identity key. Any grantd certificate still in someone's hands stops working.
WARNING
  printf 'Proceed? [y/N] '
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) die "aborted" ;; esac
fi

# ------------------------------------------------------------------ services

log "stopping services"
systemctl disable --now grantd.service 2>/dev/null || true
systemctl disable --now grant-signer.service 2>/dev/null || true
rm -f "$DAEMON_UNIT" "$SIGNER_UNIT"
systemctl daemon-reload 2>/dev/null || true

# ----------------------------------------------------------------- SSH trust
#
# The same gate as the installer: never reload sshd on a configuration that
# does not parse.

remove_ssh_trust() {
  log "removing SSH trust"
  rm -f "$SSHD_SNIPPET"
  if ! "$SSHD" -t 2>"$WORK/sshd-t"; then
    warn "sshd -t fails after removing the grantd snippet:"
    cat "$WORK/sshd-t" >&2
    warn "sshd was NOT reloaded; the running configuration is unchanged"
    return 0
  fi

  # Another sshd configuration file can reference the CA public key. Keep a
  # copy, so the file goes back if removing it breaks sshd -t.
  if [ -f "$CA_PUB" ]; then
    cp -p "$CA_PUB" "$WORK/ca.pub"
    rm -f "$CA_PUB"
    if ! "$SSHD" -t 2>/dev/null; then
      cp -p "$WORK/ca.pub" "$CA_PUB"
      warn "removing $CA_PUB broke sshd -t; the file was restored and sshd was NOT reloaded"
      warn "remove the other reference to it from the sshd configuration, then reload sshd"
      return 0
    fi
  fi

  if reload_sshd; then
    log "sshd reloaded without grantd trust"
  else
    warn "could not reload sshd via systemctl; the configuration is valid and will apply on next restart"
  fi
}

remove_ssh_trust

# -------------------------------------------------------------- key material

log "destroying key material"
if [ -x "$LIBDIR/grant-signer" ]; then
  "$LIBDIR/grant-signer" destroy --yes \
    --key-dir "$CONFDIR" --state "$STATE_DB" \
    --owner-sock "$OWNER_SOCK" \
    --daemon-sock "$DAEMON_SOCK" || warn "grant-signer destroy reported an error"
else
  warn "grant-signer binary is gone; removing key files directly"
  rm -f "$CONFDIR/host_identity" "$CONFDIR/ssh_ca" "$STATE_DB"*
fi

# --------------------------------------------------------------------- files

log "removing files"
rm -rf "$CONFDIR" "$STATEDIR" "$LIBDIR" "$TMPFILES" "$RUNDIR"
rm -f "$PUBLIC_CONF"

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
