#!/usr/bin/env bash
#
# grantd installer.
#
# The single worst thing this script could do is leave a remote machine without
# working SSH. Everything about its structure follows from that: the existing
# sshd configuration is captured before anything is touched, `sshd -t` gates the
# reload, and any failure — at any point — restores what was there before.
set -euo pipefail

VERSION="${GRANTD_VERSION:-}"
ORIGIN=""
PUBLIC_ORIGIN=""
SSH_USER=""
ADVERTISE_HOST=""
ADVERTISE_PORT="22"
RELEASES_URL=""
LOCAL_DIR=""
ASSUME_YES=0

LIBDIR=/usr/local/lib/grantd
BINDIR=/usr/local/bin
CONFDIR=/etc/grantd
STATEDIR=/var/lib/grant-signer
PUBLIC_CONF=/etc/grantd.conf
SSHD_SNIPPET=/etc/ssh/sshd_config.d/60-grantd.conf
CA_PUB=/etc/ssh/grantd_user_ca.pub
TMPFILES=/usr/lib/tmpfiles.d/grantd.conf

# The release signing key. Its private half lives offline, on a hardware token
# or an air-gapped machine, and deliberately not in the release infrastructure:
# if a compromise of the build or distribution system were sufficient to sign a
# release, the signature would be decoration.
RELEASE_SIGNER_KEY="${GRANTD_RELEASE_KEY:-}"

usage() {
  cat >&2 <<USAGE
grantd installer

  sudo ./install.sh --origin URL --ssh-user ACCOUNT --hostname ADDRESS [options]

Required:
  --origin URL        coordination service, e.g. https://grantd.example.workers.dev
  --ssh-user ACCOUNT  the login account visiting agents will use (not root)
  --hostname ADDRESS  the address a visiting agent will SSH to

Options:
  --public-origin URL  origin to embed in capability URLs (default: --origin)
  --port N             SSH port to advertise (default 22)
  --version V          release to install (default: latest from the manifest)
  --releases-url URL   where to fetch artifacts (default: ORIGIN/releases)
  --local-dir DIR      install from already-built binaries instead of downloading
  --yes                do not prompt

This installer never reloads sshd on a configuration that does not pass
'sshd -t', and restores the previous SSH configuration if anything fails.
USAGE
}

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m==> %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --origin) ORIGIN="$2"; shift 2 ;;
    --public-origin) PUBLIC_ORIGIN="$2"; shift 2 ;;
    --ssh-user) SSH_USER="$2"; shift 2 ;;
    --hostname) ADVERTISE_HOST="$2"; shift 2 ;;
    --port) ADVERTISE_PORT="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --releases-url) RELEASES_URL="$2"; shift 2 ;;
    --local-dir) LOCAL_DIR="$2"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument: $1" ;;
  esac
done

# ------------------------------------------------------------------ preflight

[ "$(id -u)" -eq 0 ] || die "install.sh must run as root"
[ -n "$ORIGIN" ] || { usage; die "--origin is required"; }
[ -n "$SSH_USER" ] || { usage; die "--ssh-user is required"; }
[ -n "$ADVERTISE_HOST" ] || { usage; die "--hostname is required"; }
[ -n "$PUBLIC_ORIGIN" ] || PUBLIC_ORIGIN="$ORIGIN"
[ -n "$RELEASES_URL" ] || RELEASES_URL="${ORIGIN%/}/releases"

# root is refused here as well as in the signer. The product's claim is that a
# visiting agent's blast radius is bounded by the enrolled account; enrolling
# root removes the bound, so it is rejected at every layer that could allow it.
[ "$SSH_USER" != "root" ] || die "refusing to enroll root; choose an unprivileged account"
id -u "$SSH_USER" >/dev/null 2>&1 || die "no such account: $SSH_USER"

command -v systemctl >/dev/null 2>&1 || die "grantd v1 requires systemd"
command -v sshd >/dev/null 2>&1 || SSHD="$(command -v /usr/sbin/sshd || true)"
SSHD="${SSHD:-$(command -v sshd || echo /usr/sbin/sshd)}"
[ -x "$SSHD" ] || die "could not find sshd"

case "$(uname -s)" in Linux) ;; *) die "grantd v1 supports Linux only" ;; esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

# Some sshd builds do not read sshd_config.d. Installing a snippet that is never
# read would silently produce a host where nothing works, so this is checked
# before anything is modified.
if ! grep -qsE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config; then
  die "/etc/ssh/sshd_config does not Include /etc/ssh/sshd_config.d/*.conf; refusing to install a snippet that sshd would ignore"
fi

log "installing grantd"
echo "    origin:        $ORIGIN"
echo "    capability URL origin: $PUBLIC_ORIGIN"
echo "    ssh user:      $SSH_USER"
echo "    advertise:     $ADVERTISE_HOST:$ADVERTISE_PORT"
echo "    architecture:  linux/$ARCH"

if [ "$ASSUME_YES" -ne 1 ]; then
  printf 'Proceed? [y/N] '
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) die "aborted" ;; esac
fi

# ----------------------------------------------------------------- rollback

WORK="$(mktemp -d)"
BACKUP="$WORK/backup"
mkdir -p "$BACKUP"
ROLLBACK_ARMED=0
SSHD_TOUCHED=0

rollback() {
  [ "$ROLLBACK_ARMED" -eq 1 ] || return 0
  warn "installation failed; restoring the previous SSH configuration"
  rm -f "$SSHD_SNIPPET" "$CA_PUB"
  if [ -f "$BACKUP/60-grantd.conf" ]; then
    cp "$BACKUP/60-grantd.conf" "$SSHD_SNIPPET"
  fi
  if [ -f "$BACKUP/grantd_user_ca.pub" ]; then
    cp "$BACKUP/grantd_user_ca.pub" "$CA_PUB"
  fi
  if [ "$SSHD_TOUCHED" -eq 1 ]; then
    if "$SSHD" -t 2>/dev/null; then
      systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
      warn "previous SSH configuration restored and reloaded"
    else
      warn "restored configuration still does not validate; sshd was NOT reloaded"
      warn "the running sshd is unchanged, so existing access is intact"
    fi
  fi
  systemctl stop grantd.service grant-signer.service 2>/dev/null || true
}
cleanup() { rm -rf "$WORK"; }
trap 'rc=$?; if [ $rc -ne 0 ]; then rollback; fi; cleanup; exit $rc' EXIT

# Capture whatever is there now, before touching anything.
[ -f "$SSHD_SNIPPET" ] && cp "$SSHD_SNIPPET" "$BACKUP/60-grantd.conf"
[ -f "$CA_PUB" ] && cp "$CA_PUB" "$BACKUP/grantd_user_ca.pub"

# The configuration must be valid *before* we start, or we cannot tell our
# breakage from breakage that was already there.
if ! "$SSHD" -t 2>"$WORK/pre-sshd-t"; then
  die "sshd -t already fails on this machine before any change:
$(cat "$WORK/pre-sshd-t")
Fix the existing SSH configuration first."
fi

# ------------------------------------------------------------------ artifacts

STAGE="$WORK/stage"
mkdir -p "$STAGE"

if [ -n "$LOCAL_DIR" ]; then
  log "installing from $LOCAL_DIR"
  for b in grantd grant-signer; do
    [ -f "$LOCAL_DIR/$b" ] || die "missing binary: $LOCAL_DIR/$b"
    cp "$LOCAL_DIR/$b" "$STAGE/$b"
  done
else
  command -v curl >/dev/null 2>&1 || die "curl is required to download a release"
  # Bounded: an unreachable or hanging release host should fail the install, not
  # wedge it. Without this a wrong --releases-url hangs indefinitely.
  CURL="curl -fsSL --connect-timeout 10 --max-time 120 --retry 2"
  if [ -z "$VERSION" ]; then
    log "resolving the latest release"
    $CURL "$RELEASES_URL/latest.json" -o "$STAGE/latest.json" \
      || die "could not fetch $RELEASES_URL/latest.json"
    VERSION="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$STAGE/latest.json" | head -1)"
    [ -n "$VERSION" ] || die "could not determine the latest version"
  fi
  log "downloading grantd $VERSION (linux/$ARCH)"
  BASE="$RELEASES_URL/$VERSION"
  for b in grantd grant-signer; do
    $CURL "$BASE/${b}-linux-${ARCH}" -o "$STAGE/$b" || die "could not download $b"
  done
  $CURL "$BASE/SHA256SUMS" -o "$STAGE/SHA256SUMS" || die "could not download SHA256SUMS"
  $CURL "$BASE/SHA256SUMS.sig" -o "$STAGE/SHA256SUMS.sig" || die "could not download SHA256SUMS.sig"

  # Signature first, then hashes. Verifying hashes against an unsigned SHA256SUMS
  # proves only that the download was not corrupted, which is not the question.
  log "verifying the release signature"
  [ -n "$RELEASE_SIGNER_KEY" ] || RELEASE_SIGNER_KEY="$(cat "$(dirname "$0")/release-signing-key.pub" 2>/dev/null || true)"
  [ -n "$RELEASE_SIGNER_KEY" ] || die "no release signing key available; refusing to install an unverified release"
  printf 'grantd-release %s\n' "$RELEASE_SIGNER_KEY" > "$WORK/allowed_signers"
  ssh-keygen -Y verify -f "$WORK/allowed_signers" -I grantd-release -n grantd-release \
      -s "$STAGE/SHA256SUMS.sig" < "$STAGE/SHA256SUMS" >/dev/null \
    || die "release signature does not verify; refusing to install"

  log "verifying artifact hashes"
  ( cd "$STAGE" && grep -E " (grantd|grant-signer)-linux-${ARCH}\$" SHA256SUMS \
      | while read -r sum name; do
          base="${name%-linux-${ARCH}}"
          echo "$sum  $base"
        done > verify.txt
    sha256sum -c verify.txt >/dev/null ) || die "artifact hash mismatch; refusing to install"
fi

chmod 0755 "$STAGE"/grantd "$STAGE"/grant-signer

# -------------------------------------------------------------------- accounts

log "creating service accounts"
getent group grantsigner >/dev/null || groupadd --system grantsigner
getent group grantd >/dev/null || groupadd --system grantd
id -u grantsigner >/dev/null 2>&1 || \
  useradd --system --gid grantsigner --no-create-home --shell /usr/sbin/nologin grantsigner
id -u grantd >/dev/null 2>&1 || \
  useradd --system --gid grantd --no-create-home --shell /usr/sbin/nologin grantd

OWNER_UID="$(id -u "$SSH_USER")"
OWNER_GID="$(id -g "$SSH_USER")"
DAEMON_UID="$(id -u grantd)"
DAEMON_GID="$(getent group grantd | cut -d: -f3)"
SIGNER_UID="$(id -u grantsigner)"

# ------------------------------------------------------------------- filesystem

log "installing binaries and state directories"
install -d -m 0755 "$LIBDIR"
for b in grantd grant-signer; do
  install -m 0755 "$STAGE/$b" "$LIBDIR/$b"
done

install -d -m 0700 -o grantsigner -g grantsigner "$CONFDIR"
install -d -m 0700 -o grantsigner -g grantsigner "$STATEDIR"

# Each socket in its own setgid directory: the kernel assigns the group at
# creation, so the unprivileged signer never needs chown, and the daemon cannot
# even traverse into the owner socket's directory.
cat > "$TMPFILES" <<TMPF
d /run/grantd 0755 root root -
d /run/grantd/owner 2770 grantsigner ${SSH_USER} -
d /run/grantd/redeem 2770 grantsigner grantd -
TMPF
systemd-tmpfiles --create "$TMPFILES"

# Public configuration, outside the key directory. The daemon's unit makes
# /etc/grantd invisible to it, so anything the daemon reads must live elsewhere;
# this file contains only the coordination service origin, which is public.
printf '%s\n' "$PUBLIC_ORIGIN" > /etc/grantd.conf
chown root:root /etc/grantd.conf
chmod 0644 /etc/grantd.conf

cat > "$CONFDIR/signer.env" <<ENV
GRANTD_OWNER_UID=$OWNER_UID
GRANTD_OWNER_GID=$OWNER_GID
GRANTD_DAEMON_UID=$DAEMON_UID
GRANTD_DAEMON_GID=$DAEMON_GID
ENV
chmod 0644 "$CONFDIR/signer.env"

# ------------------------------------------------------------------ enrollment

ROLLBACK_ARMED=1

log "generating host identity and SSH CA"
runuser -u grantsigner -- "$LIBDIR/grant-signer" init \
  --ssh-user "$SSH_USER" \
  --hostname "$ADVERTISE_HOST" \
  --port "$ADVERTISE_PORT" \
  --origin "$PUBLIC_ORIGIN" > "$WORK/enroll.json" \
  || die "enrollment failed"

HOST_ID="$(sed -n 's/.*"host_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$WORK/enroll.json")"
[ -n "$HOST_ID" ] || die "enrollment did not produce a host id"

# sshd runs as root and must read the CA public key, but /etc/grantd is 0700 to
# the signer. Copy the public half out rather than loosening the directory.
install -m 0644 -o root -g root "$CONFDIR/ssh_ca.pub" "$CA_PUB"

# --------------------------------------------------------------------- sshd

log "configuring sshd"
SSHD_TOUCHED=1
cat > "$SSHD_SNIPPET" <<CONF
# Managed by grantd. Remove with grantd's uninstall.sh.
#
# Trusts certificates issued by this machine's own CA. The CA private key is
# held by the grantsigner account and never leaves this machine.
TrustedUserCAKeys $CA_PUB
CONF
chmod 0644 "$SSHD_SNIPPET"

# The gate. sshd is never reloaded on a configuration that does not parse.
if ! "$SSHD" -t 2>"$WORK/sshd-t"; then
  warn "sshd -t rejected the new configuration:"
  cat "$WORK/sshd-t" >&2
  die "refusing to reload sshd"
fi
log "sshd -t passed"

if ! (systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null); then
  warn "could not reload sshd via systemctl; the configuration is valid and will apply on next restart"
fi

# --------------------------------------------------------------------- units

log "installing systemd units"
UNIT_SRC="$(dirname "$0")/systemd"
if [ -d "$UNIT_SRC" ]; then
  install -m 0644 "$UNIT_SRC/grant-signer.service" /etc/systemd/system/grant-signer.service
  install -m 0644 "$UNIT_SRC/grantd.service" /etc/systemd/system/grantd.service
else
  die "systemd unit files not found next to install.sh"
fi
systemctl daemon-reload
systemctl enable --now grant-signer.service >/dev/null
systemctl enable --now grantd.service >/dev/null

# -------------------------------------------------------------------- health

log "waiting for the signer and daemon"
for _ in $(seq 1 40); do
  if [ -S /run/grantd/owner/owner.sock ] && [ -S /run/grantd/redeem/redeem.sock ]; then break; fi
  sleep 0.25
done
[ -S /run/grantd/owner/owner.sock ] || die "signer did not create its owner socket"

if ! runuser -u "$SSH_USER" -- curl -sf --unix-socket /run/grantd/owner/owner.sock \
      http://localhost/status >"$WORK/status.json" 2>/dev/null; then
  warn "could not read status through the owner socket as $SSH_USER"
fi

ONLINE=no
for _ in $(seq 1 40); do
  if journalctl -u grantd.service --since "-2 min" 2>/dev/null | grep -q "rendezvous connected"; then
    ONLINE=yes; break
  fi
  sleep 0.5
done

ROLLBACK_ARMED=0

cat <<DONE

$(log "grantd installed")

    host id:    $HOST_ID
    ssh user:   $SSH_USER
    advertised: $ADVERTISE_HOST:$ADVERTISE_PORT
    rendezvous: $ONLINE

Mint a 30-minute capability as $SSH_USER:

    curl -s --unix-socket /run/grantd/owner/owner.sock \\
      -X POST http://localhost/grants \\
      -H 'content-type: application/json' \\
      -d '{"ttl_seconds":1800}'

The capability_url in the reply is the whole thing. There is no client to
install: the owner API is a Unix socket, and a recipient redeems with curl,
openssl and ssh-keygen.

Send the whole URL, including the part after '#', to the recipient over a
channel you trust. That fragment is the capability; this machine keeps the only
other copy, and the coordination service never sees it.

Automatic updates are deliberately not installed.
DONE
