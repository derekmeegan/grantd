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

# The release signing key, embedded so this script is a self-contained artifact.
# Its private half lives offline — on a hardware token or an air-gapped machine,
# and deliberately not in the release infrastructure. If a compromise of the
# build or distribution system were enough to sign a release, the signature
# would be decoration.
#
# Be clear about what this buys, since it is easy to overstate. Embedding the
# key means the trust anchor travels with the script rather than being fetched
# from the same bucket as the artifacts it is meant to vouch for — that
# arrangement would be circular and worthless. It does not make `curl | sh` from
# an origin safe: at that moment you are trusting the origin to hand you an
# honest script. The signature's real value is when this script arrives some
# other way — a git checkout, a package, a copy you have read — and the release
# bucket is the thing you are unsure about.
RELEASE_SIGNER_KEY="${GRANTD_RELEASE_KEY:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN+NinC05+tSWFnXFK1Fkb7H0t5emBjKJKgd/ZSKO7UP grantd release signing (test)}"

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
# The units live here rather than in adjacent files, so this script is a single
# self-contained artifact that works when curled. Two copies of a unit that
# confines the trust root is two copies that can drift apart, and the one that
# matters is whichever the installer happened to write.
cat > /etc/systemd/system/grant-signer.service <<'GRANT_SIGNER_UNIT'
[Unit]
Description=grantd signer (local trust root)
Documentation=https://github.com/derekmeegan/grantd
After=local-fs.target systemd-tmpfiles-setup.service
Before=grantd.service

[Service]
Type=simple
User=grantsigner
Group=grantsigner

# The socket directories come from /usr/lib/tmpfiles.d/grantd.conf, which
# systemd-tmpfiles-setup.service applies at boot — /run is a tmpfs, so they are
# recreated every time. They are setgid, so the unprivileged signer ends up with
# owner.sock in the owner's group and redeem.sock in the daemon's, needing
# neither CAP_CHOWN nor membership in either group.
#
# This unit deliberately does not re-run systemd-tmpfiles itself. Doing so spawns
# a privileged helper inside this unit's sandbox on every start, which is both
# redundant and a failure mode of its own: the spawn has to set up the private
# network namespace before it can run, and when that fails the trust root does
# not start at all.
ExecStart=/usr/local/lib/grantd/grant-signer serve \
    --owner-sock /run/grantd/owner/owner.sock \
    --daemon-sock /run/grantd/redeem/redeem.sock \
    --owner-uid ${GRANTD_OWNER_UID} \
    --owner-gid ${GRANTD_OWNER_GID} \
    --daemon-uid ${GRANTD_DAEMON_UID} \
    --daemon-gid ${GRANTD_DAEMON_GID}
EnvironmentFile=/etc/grantd/signer.env

Restart=always
RestartSec=2

# This process holds the SSH CA key and the host identity key. It has no reason
# to ever touch the network, so it is placed in a namespace where it cannot:
# PrivateNetwork leaves it with loopback only, and AF_UNIX is the only address
# family it can even open. Unix sockets are filesystem objects and keep working.
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any

NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/grant-signer /run/grantd
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
# @privileged stays denied. The signer never needs to chown anything: the socket
# directories are setgid, so the kernel assigns the right group at creation, and
# the signer verifies that rather than changing it. A denied syscall under
# seccomp raises SIGSYS and kills the process rather than returning an error, so
# "deny it and let the code fall back" is not an option — the code has to not
# make the call.
SystemCallFilter=~@privileged @resources @obsolete @mount @swap @reboot @raw-io
UMask=0077

[Install]
WantedBy=multi-user.target
GRANT_SIGNER_UNIT
cat > /etc/systemd/system/grantd.service <<'GRANTD_UNIT'
[Unit]
Description=grantd daemon (coordination rendezvous)
Documentation=https://github.com/derekmeegan/grantd
After=network-online.target grant-signer.service
Wants=network-online.target
Requires=grant-signer.service

[Service]
Type=simple
User=grantd
Group=grantd

# The origin lives in a public file, not in /etc/grantd. That directory holds
# both private keys and is made invisible to this process below, so anything the
# daemon needs to read has to live outside it.
ExecStart=/usr/local/lib/grantd/grantd \
    --signer-sock /run/grantd/redeem/redeem.sock \
    --origin-file /etc/grantd.conf

Restart=always
RestartSec=2

# This is the process the threat model assumes gets compromised. It needs
# outbound TCP and one Unix socket, and nothing else — so it is given nothing
# else. In particular /etc/grantd, which holds both private keys, is made
# invisible to it, on top of the file permissions that already exclude it.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
InaccessiblePaths=/etc/grantd /var/lib/grant-signer /run/grantd/owner
ReadWritePaths=/run/grantd/redeem
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete @mount @swap @reboot @raw-io
UMask=0077

[Install]
WantedBy=multi-user.target
GRANTD_UNIT
chmod 0644 /etc/systemd/system/grant-signer.service /etc/systemd/system/grantd.service
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
