#!/usr/bin/env bash
#
# grantd installer.
#
# The installer must never leave a machine without working SSH. It records
# the sshd configuration before it changes anything. It never reloads sshd on
# a configuration that fails `sshd -t`. If any step fails, it undoes every
# change it made and restores what it found.
set -euo pipefail

# ------------------------------------------------------------------ settings

VERSION="${GRANTD_VERSION:-}"
ORIGIN=""
PUBLIC_ORIGIN=""
SSH_USER=""
ADVERTISE_HOST=""
ADVERTISE_PORT="22"
LISTEN_PORT=""
RELEASES_URL=""
LOCAL_DIR=""
RELEASE_KEY=""
ASSUME_YES=0

LIBDIR=/usr/local/lib/grantd
CONFDIR=/etc/grantd
STATEDIR=/var/lib/grant-signer
STATE_DB=/var/lib/grant-signer/state.db
PUBLIC_CONF=/etc/grantd.conf
SIGNER_ENV=/etc/grantd/signer.env
SSHD_SNIPPET=/etc/ssh/sshd_config.d/60-grantd.conf
CA_PUB=/etc/ssh/grantd_user_ca.pub
TMPFILES=/usr/lib/tmpfiles.d/grantd.conf
RUNDIR=/run/grantd
OWNER_SOCK=/run/grantd/owner/owner.sock
DAEMON_SOCK=/run/grantd/redeem/redeem.sock
SIGNER_UNIT=/etc/systemd/system/grant-signer.service
DAEMON_UNIT=/etc/systemd/system/grantd.service

# The release signing key. It is embedded so this script is one self-contained
# artifact. The private half lives offline and is not in the release
# infrastructure.
#
# The embedded key does not make `curl | sh` safe. At that moment you trust the
# origin to hand you an honest script. The signature matters when this script
# arrives another way (a git checkout, a package, a copy you have read) and the
# release bucket is the thing you are unsure about.
DEFAULT_RELEASE_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN+NinC05+tSWFnXFK1Fkb7H0t5emBjKJKgd/ZSKO7UP"

# ------------------------------------------------------------------- helpers

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m==> %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<USAGE
grantd installer

  sudo ./install.sh --origin URL --ssh-user ACCOUNT --hostname ADDRESS [options]

Required:
  --origin URL         coordination service, e.g. https://grantd.example.workers.dev
  --ssh-user ACCOUNT   the login account visiting agents will use (not root)
  --hostname ADDRESS   the address a visiting agent will SSH to

Options:
  --public-origin URL  origin to embed in capability URLs (default: --origin)
  --port N             SSH port to advertise (default 22)
  --listen-port N      also make sshd listen on N, and advertise N. Use 443 for
                       visitors in sandboxes that allow no other outbound port.
                       Existing listeners are kept.
  --version V          release to install (default: latest from the manifest)
  --releases-url URL   where to fetch artifacts (default: ORIGIN/releases)
  --release-key KEY    ssh-ed25519 public key that must have signed the release
                       (default: the key embedded in this script)
  --local-dir DIR      install from already-built binaries instead of downloading
  --yes                do not prompt

This installer never reloads sshd on a configuration that does not pass
'sshd -t', and restores the previous SSH configuration if anything fails.
USAGE
}

# json_str FILE KEY: print the string value of KEY from a small flat JSON file.
json_str() {
  sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" | head -1
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
    --origin) ORIGIN="$2"; shift 2 ;;
    --public-origin) PUBLIC_ORIGIN="$2"; shift 2 ;;
    --ssh-user) SSH_USER="$2"; shift 2 ;;
    --hostname) ADVERTISE_HOST="$2"; shift 2 ;;
    --port) ADVERTISE_PORT="$2"; shift 2 ;;
    --listen-port) LISTEN_PORT="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --releases-url) RELEASES_URL="$2"; shift 2 ;;
    --release-key) RELEASE_KEY="$2"; shift 2 ;;
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
[ -n "$RELEASE_KEY" ] || RELEASE_KEY="$DEFAULT_RELEASE_KEY"

# The account can arrive as a name or a numeric uid. Keep the name from here
# on. Root is refused here and again in the signer: the product's claim is
# that a visitor's reach is bounded by the enrolled account.
id -u "$SSH_USER" >/dev/null 2>&1 || die "no such account: $SSH_USER"
SSH_USER="$(id -un "$SSH_USER")"
[ "$(id -u "$SSH_USER")" -ne 0 ] || die "refusing to enroll root; choose an unprivileged account"
OWNER_UID="$(id -u "$SSH_USER")"
OWNER_GID="$(id -g "$SSH_USER")"

command -v systemctl >/dev/null 2>&1 || die "grantd v1 requires systemd"
SSHD="$(find_sshd)" || die "could not find sshd"

# A visiting agent in a locked-down sandbox often reaches port 443 and nothing
# else. --listen-port adds a listener there without disturbing the existing
# ones, so the operator's own access on port 22 keeps working.
if [ -n "$LISTEN_PORT" ]; then
  case "$LISTEN_PORT" in
    ''|*[!0-9]*) die "--listen-port must be a number" ;;
  esac
  [ "$LISTEN_PORT" -ge 1 ] && [ "$LISTEN_PORT" -le 65535 ] \
    || die "--listen-port $LISTEN_PORT is out of range"
  # An explicit --port wins. Otherwise advertise the port we are adding.
  case " $* " in *" --port "*) ;; *) ADVERTISE_PORT="$LISTEN_PORT" ;; esac
fi

case "$(uname -s)" in Linux) ;; *) die "grantd v1 supports Linux only" ;; esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

# Some sshd builds do not read sshd_config.d. A snippet that sshd never reads
# gives a host where nothing works, so check before anything changes.
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

# ------------------------------------------------------------------ rollback
#
# Every change records the command that undoes it. On failure the commands run
# in reverse order, so services stop before their files go and SSH trust is
# put back before key material is removed.

WORK="$(mktemp -d)"
BACKUP="$WORK/backup"
mkdir -p "$BACKUP"
ROLLBACK_ARMED=0
SSHD_TOUCHED=0
UNDO=()

undo() { UNDO+=("$1"); }

# track_file PATH: if PATH exists, save a copy and restore it on rollback.
# If PATH does not exist, remove it on rollback.
track_file() {
  if [ -e "$1" ]; then
    saved="$BACKUP/$(printf '%s' "$1" | tr / _)"
    cp -p "$1" "$saved"
    undo "cp -p '$saved' '$1'"
  else
    undo "rm -f '$1'"
  fi
}

# track_new PATH: if PATH does not exist, remove it on rollback. Existing
# paths are left alone. Use this for private keys, which are never copied.
track_new() {
  [ -e "$1" ] || undo "rm -rf '$1'"
}

# track_unit NAME PATH: restore a unit that existed, or disable and remove a
# new one.
track_unit() {
  if [ -e "$2" ]; then
    saved="$BACKUP/$(basename "$2")"
    cp -p "$2" "$saved"
    undo "systemctl restart '$1'"
    undo "systemctl daemon-reload"
    undo "cp -p '$saved' '$2'"
  else
    undo "systemctl daemon-reload"
    undo "rm -f '$2'"
    undo "systemctl disable --now '$1'"
  fi
}

ensure_group() {
  getent group "$1" >/dev/null && return 0
  groupadd --system "$1"
  undo "groupdel '$1'"
}

ensure_user() {
  id -u "$1" >/dev/null 2>&1 && return 0
  useradd --system --gid "$1" --no-create-home --shell /usr/sbin/nologin "$1"
  undo "userdel '$1'"
}

# ensure_dir MODE OWNER GROUP PATH
ensure_dir() {
  [ -d "$4" ] || undo "rm -rf '$4'"
  install -d -m "$1" -o "$2" -g "$3" "$4"
}

rollback() {
  [ "$ROLLBACK_ARMED" -eq 1 ] || return 0
  warn "installation failed; undoing every change and restoring the previous SSH configuration"
  i=${#UNDO[@]}
  while [ "$i" -gt 0 ]; do
    i=$((i - 1))
    eval "${UNDO[$i]}" 2>/dev/null || true
  done
  [ "$SSHD_TOUCHED" -eq 1 ] || return 0
  if "$SSHD" -t 2>/dev/null; then
    reload_sshd || true
    warn "previous SSH configuration restored and reloaded"
  else
    warn "restored configuration still does not validate; sshd was NOT reloaded"
    warn "the running sshd is unchanged, so existing access is intact"
  fi
}

cleanup() { rm -rf "$WORK"; }
trap 'rc=$?; if [ $rc -ne 0 ]; then rollback; fi; cleanup; exit $rc' EXIT

# The configuration must be valid before the install starts. Otherwise the
# installer cannot tell its own breakage from breakage that was already there.
if ! "$SSHD" -t 2>"$WORK/pre-sshd-t"; then
  die "sshd -t already fails on this machine before any change:
$(cat "$WORK/pre-sshd-t")
Fix the existing SSH configuration first."
fi

ROLLBACK_ARMED=1

# ----------------------------------------------------------------- artifacts

STAGE="$WORK/stage"
mkdir -p "$STAGE"

stage_local() {
  log "installing from $LOCAL_DIR"
  for b in grantd grant-signer; do
    [ -f "$LOCAL_DIR/$b" ] || die "missing binary: $LOCAL_DIR/$b"
    cp "$LOCAL_DIR/$b" "$STAGE/$b"
  done
}

# Bounded timeouts: an unreachable release host must fail the install, not
# hang it. On https origins, refuse a redirect to plain http.
CURL=(curl -fsSL --connect-timeout 10 --max-time 120 --retry 2)
case "$RELEASES_URL" in
  https://*) CURL+=(--proto '=https' --proto-redir '=https') ;;
esac

fetch() { "${CURL[@]}" "$1" -o "$2"; }

resolve_version() {
  [ -z "$VERSION" ] || return 0
  log "resolving the latest release"
  fetch "$RELEASES_URL/latest.json" "$STAGE/latest.json" \
    || die "could not fetch $RELEASES_URL/latest.json"
  VERSION="$(json_str "$STAGE/latest.json" version)"
  [ -n "$VERSION" ] || die "could not determine the latest version"
}

download_release() {
  log "downloading grantd $VERSION (linux/$ARCH)"
  for f in "grantd-linux-$ARCH" "grant-signer-linux-$ARCH" VERSION SHA256SUMS SHA256SUMS.sig; do
    fetch "$RELEASES_URL/$VERSION/$f" "$STAGE/$f" || die "could not download $f"
  done
}

# Signature first, then hashes. Hashes from an unsigned SHA256SUMS only prove
# that the download was not corrupted.
verify_signature() {
  log "verifying the release signature"
  printf 'grantd-release %s\n' "$RELEASE_KEY" > "$WORK/allowed_signers"
  ssh-keygen -Y verify -f "$WORK/allowed_signers" -I grantd-release -n grantd-release \
      -s "$STAGE/SHA256SUMS.sig" < "$STAGE/SHA256SUMS" >/dev/null \
    || die "release signature does not verify; refusing to install"
}

# Each expected artifact must appear exactly once in the signed list, and
# every listed line must check out. A missing line is a rejection, not a skip.
verify_hashes() {
  log "verifying artifact hashes"
  : > "$STAGE/verify.txt"
  for f in "grantd-linux-$ARCH" "grant-signer-linux-$ARCH" VERSION; do
    n="$(grep -cE "^[0-9a-f]{64}  $f\$" "$STAGE/SHA256SUMS" || true)"
    [ "$n" -eq 1 ] || die "signed SHA256SUMS lists $f $n times; expected exactly once"
    grep -E "^[0-9a-f]{64}  $f\$" "$STAGE/SHA256SUMS" >> "$STAGE/verify.txt"
  done
  ( cd "$STAGE" && sha256sum -c --strict verify.txt >/dev/null 2>&1 ) \
    || die "artifact hash mismatch; refusing to install"
}

# The signed VERSION file binds the hash list to one release. Without it, an
# older signed release served under a newer version path installs silently.
verify_version() {
  signed="$(tr -d '[:space:]' < "$STAGE/VERSION")"
  [ "$signed" = "$VERSION" ] \
    || die "the signed release is $signed but $VERSION was requested; refusing to install"
  log "release $VERSION is signed and complete"
}

if [ -n "$LOCAL_DIR" ]; then
  stage_local
else
  command -v curl >/dev/null 2>&1 || die "curl is required to download a release"
  resolve_version
  download_release
  verify_signature
  verify_hashes
  verify_version
  cp "$STAGE/grantd-linux-$ARCH" "$STAGE/grantd"
  cp "$STAGE/grant-signer-linux-$ARCH" "$STAGE/grant-signer"
fi
chmod 0755 "$STAGE/grantd" "$STAGE/grant-signer"

# ------------------------------------------------------------------ accounts

log "creating service accounts"
ensure_group grantsigner
ensure_group grantd
ensure_user grantsigner
ensure_user grantd

DAEMON_UID="$(id -u grantd)"
DAEMON_GID="$(getent group grantd | cut -d: -f3)"

# ---------------------------------------------------------------- filesystem

log "installing binaries and state directories"
ensure_dir 0755 root root "$LIBDIR"
for b in grantd grant-signer; do
  track_file "$LIBDIR/$b"
  install -m 0755 "$STAGE/$b" "$LIBDIR/$b"
done

ensure_dir 0700 grantsigner grantsigner "$CONFDIR"
ensure_dir 0700 grantsigner grantsigner "$STATEDIR"

# Each socket lives in its own setgid directory. The kernel assigns the group
# at creation, so the unprivileged signer never needs chown. The daemon cannot
# traverse into the owner socket's directory. Groups are numeric: the owner's
# primary group does not always share the owner's name.
track_file "$TMPFILES"
cat > "$TMPFILES" <<TMPF
d $RUNDIR 0755 root root -
d $RUNDIR/owner 2770 grantsigner $OWNER_GID -
d $RUNDIR/redeem 2770 grantsigner $DAEMON_GID -
TMPF
[ -d "$RUNDIR" ] || undo "rm -rf '$RUNDIR'"
systemd-tmpfiles --create "$TMPFILES"

# The daemon's unit hides /etc/grantd from it, so the origin lives in a
# separate public file.
track_file "$PUBLIC_CONF"
printf '%s\n' "$PUBLIC_ORIGIN" > "$PUBLIC_CONF"
chown root:root "$PUBLIC_CONF"
chmod 0644 "$PUBLIC_CONF"

track_file "$SIGNER_ENV"
cat > "$SIGNER_ENV" <<ENV
GRANTD_OWNER_UID=$OWNER_UID
GRANTD_OWNER_GID=$OWNER_GID
GRANTD_DAEMON_UID=$DAEMON_UID
GRANTD_DAEMON_GID=$DAEMON_GID
ENV
chmod 0644 "$SIGNER_ENV"

# ---------------------------------------------------------------- enrollment

log "generating host identity and SSH CA"
for f in host_identity ssh_ca ssh_ca.pub; do
  track_new "$CONFDIR/$f"
done
track_file "$CONFDIR/origin"
for f in "$STATE_DB" "$STATE_DB-wal" "$STATE_DB-shm"; do
  track_new "$f"
done

# A clean environment: the signer reads GRANTD_* variables, and a stray one
# from the caller's shell must not move the keys somewhere the unit does not
# look. The paths are passed explicitly and match the unit below.
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  runuser -u grantsigner -- "$LIBDIR/grant-signer" init \
    --key-dir "$CONFDIR" \
    --state "$STATE_DB" \
    --ssh-user "$SSH_USER" \
    --hostname "$ADVERTISE_HOST" \
    --port "$ADVERTISE_PORT" \
    --origin "$PUBLIC_ORIGIN" > "$WORK/enroll.json" \
  || die "enrollment failed"

HOST_ID="$(json_str "$WORK/enroll.json" host_id)"
[ -n "$HOST_ID" ] || die "enrollment did not produce a host id"

# ---------------------------------------------------------------------- sshd

log "configuring sshd"

# sshd runs as root and must read the CA public key, but /etc/grantd is 0700
# to the signer. Copy the public half out instead of loosening the directory.
track_file "$CA_PUB"
install -m 0644 -o root -g root "$CONFDIR/ssh_ca.pub" "$CA_PUB"

track_file "$SSHD_SNIPPET"
SSHD_TOUCHED=1
cat > "$SSHD_SNIPPET" <<CONF
# Managed by grantd. Remove with grantd's uninstall.sh.
#
# Trusts certificates issued by this machine's own CA. The CA private key is
# held by the grantsigner account and never leaves this machine.
TrustedUserCAKeys $CA_PUB
CONF

# Adding a listener means naming every port, because a Port directive replaces
# the default rather than adding to it. Read the ports sshd uses now and write
# all of them back, so the operator's own access cannot be removed here.
if [ -n "$LISTEN_PORT" ]; then
  CURRENT_PORTS="$("$SSHD" -T 2>/dev/null | awk 'tolower($1) == "port" { print $2 }')"
  [ -n "$CURRENT_PORTS" ] || CURRENT_PORTS=22
  if printf '%s\n' "$CURRENT_PORTS" | grep -qx "$LISTEN_PORT"; then
    log "sshd already listens on $LISTEN_PORT"
  else
    # Refuse if another service holds the port. sshd would fail to bind on its
    # next restart, and that failure would arrive long after this install.
    if command -v ss >/dev/null 2>&1 && ss -ltnH "sport = :$LISTEN_PORT" 2>/dev/null | grep -q .; then
      die "something already listens on port $LISTEN_PORT; choose another --listen-port"
    fi
    {
      echo
      echo "# Listeners. Every existing port is repeated, because a Port"
      echo "# directive replaces the default instead of adding to it."
      printf 'Port %s\n' $CURRENT_PORTS
      printf 'Port %s\n' "$LISTEN_PORT"
    } >> "$SSHD_SNIPPET"
    log "adding an sshd listener on port $LISTEN_PORT, keeping $(echo $CURRENT_PORTS | tr '\n' ' ')"
  fi
fi
chmod 0644 "$SSHD_SNIPPET"

# The gate. sshd is never reloaded on a configuration that does not parse.
if ! "$SSHD" -t 2>"$WORK/sshd-t"; then
  warn "sshd -t rejected the new configuration:"
  cat "$WORK/sshd-t" >&2
  die "refusing to reload sshd"
fi
log "sshd -t passed"

# sshd keeps the first TrustedUserCAKeys it reads. If another file sets it
# first, the grantd snippet is ignored and no certificate will ever work.
EFFECTIVE_CA="$("$SSHD" -T 2>/dev/null | awk 'tolower($1) == "trustedusercakeys" { print $2 }' | head -1)"
if [ "$EFFECTIVE_CA" != "$CA_PUB" ]; then
  die "sshd -T reports trustedusercakeys '${EFFECTIVE_CA:-none}', not $CA_PUB.
Another sshd configuration file sets TrustedUserCAKeys before $SSHD_SNIPPET,
so the grantd snippet has no effect. Remove or reorder that setting, then re-run."
fi
log "sshd will trust $CA_PUB"

# A Port directive takes effect only on a restart. A reload does not rebind.
if [ -n "$LISTEN_PORT" ] && ! "$SSHD" -T 2>/dev/null | awk 'tolower($1) == "port" { print $2 }' | grep -qx "$ADVERTISE_PORT"; then
  die "sshd -T does not report port $ADVERTISE_PORT after writing the snippet"
fi
if [ -n "$LISTEN_PORT" ]; then
  # Ubuntu 24.04 and later put sshd behind socket activation. A systemd
  # generator turns the Port directives into the socket's ListenStream, so the
  # generator has to run and the socket has to rebind. Restarting the service
  # alone changes nothing there. Established sessions live in their own
  # per-connection units and survive this.
  if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl restart ssh.socket 2>/dev/null \
      || warn "could not restart ssh.socket; the new listener starts with the next restart"
  else
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null \
      || warn "could not restart sshd; the new listener starts with the next restart"
  fi
  for _ in $(seq 1 20); do
    if command -v ss >/dev/null 2>&1 && ss -ltnH "sport = :$LISTEN_PORT" 2>/dev/null | grep -q .; then break; fi
    sleep 0.25
  done
  if command -v ss >/dev/null 2>&1 && ! ss -ltnH "sport = :$LISTEN_PORT" 2>/dev/null | grep -q .; then
    warn "sshd is not listening on $LISTEN_PORT yet; check 'systemctl status ssh'"
  else
    log "sshd is listening on $LISTEN_PORT"
  fi
  # A host firewall silently defeats the new listener.
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw status 2>/dev/null | grep -q "^$LISTEN_PORT" \
      || warn "ufw is active and has no rule for $LISTEN_PORT; run: ufw allow $LISTEN_PORT/tcp"
  fi
elif ! reload_sshd; then
  warn "could not reload sshd via systemctl; the configuration is valid and will apply on next restart"
fi

# --------------------------------------------------------------------- units
#
# The units live in this script so it stays one self-contained artifact that
# works when curled. The unit that confines the trust root must not have a
# second copy that can drift.

log "installing systemd units"
track_unit grant-signer.service "$SIGNER_UNIT"
cat > "$SIGNER_UNIT" <<'GRANT_SIGNER_UNIT'
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
# systemd-tmpfiles-setup.service applies at boot. /run is a tmpfs, so they
# are recreated every time. They are setgid, so the unprivileged signer gets
# owner.sock in the owner's group and redeem.sock in the daemon's group.
#
# This unit does not re-run systemd-tmpfiles itself. That spawns a privileged
# helper inside this sandbox on every start. When the private network
# namespace fails to set up, the helper fails and the trust root does not start.
ExecStart=/usr/local/lib/grantd/grant-signer serve \
    --key-dir /etc/grantd \
    --state /var/lib/grant-signer/state.db \
    --owner-sock /run/grantd/owner/owner.sock \
    --daemon-sock /run/grantd/redeem/redeem.sock \
    --owner-uid ${GRANTD_OWNER_UID} \
    --owner-gid ${GRANTD_OWNER_GID} \
    --daemon-uid ${GRANTD_DAEMON_UID} \
    --daemon-gid ${GRANTD_DAEMON_GID}
EnvironmentFile=/etc/grantd/signer.env

Restart=always
RestartSec=2

# This process holds the SSH CA key and the host identity key. It never needs
# the network. PrivateNetwork leaves it with loopback only, and AF_UNIX is the
# only address family it can open. Unix sockets are filesystem objects and
# keep working.
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
# @privileged stays denied. The signer never chowns anything: the socket
# directories are setgid, so the kernel assigns the group at creation. A
# denied syscall under seccomp raises SIGSYS and kills the process instead of
# returning an error, so the code must not make the call at all.
SystemCallFilter=~@privileged @resources @obsolete @mount @swap @reboot @raw-io
UMask=0077

[Install]
WantedBy=multi-user.target
GRANT_SIGNER_UNIT

track_unit grantd.service "$DAEMON_UNIT"
cat > "$DAEMON_UNIT" <<'GRANTD_UNIT'
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
# both private keys and is made invisible to this process below.
ExecStart=/usr/local/lib/grantd/grantd \
    --signer-sock /run/grantd/redeem/redeem.sock \
    --origin-file /etc/grantd.conf

Restart=always
RestartSec=2

# The threat model assumes this process gets compromised. It needs outbound
# TCP and one Unix socket, and it gets nothing else. /etc/grantd holds both
# private keys and is made invisible, on top of the file permissions that
# already exclude it.
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

chmod 0644 "$SIGNER_UNIT" "$DAEMON_UNIT"
systemctl daemon-reload
systemctl enable grant-signer.service grantd.service >/dev/null
# restart, not start: on a re-install the running services must pick up the
# new binaries.
systemctl restart grant-signer.service
systemctl restart grantd.service

# -------------------------------------------------------------------- health

log "waiting for the signer and daemon"
for _ in $(seq 1 40); do
  if [ -S "$OWNER_SOCK" ] && [ -S "$DAEMON_SOCK" ]; then break; fi
  sleep 0.25
done
[ -S "$OWNER_SOCK" ] || die "signer did not create its owner socket"

if ! runuser -u "$SSH_USER" -- curl -sf --unix-socket "$OWNER_SOCK" \
      http://localhost/status >"$WORK/status.json" 2>/dev/null; then
  warn "could not read status through the owner socket as $SSH_USER"
fi

ONLINE=no
for _ in $(seq 1 40); do
  if journalctl -u grantd.service --since "-2 min" 2>/dev/null | grep -q "rendezvous connected"; then
    ONLINE=yes
    break
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

    curl -s --unix-socket $OWNER_SOCK \\
      -X POST http://localhost/grants \\
      -H 'content-type: application/json' \\
      -d '{"ttl_seconds":1800}'

The capability_url in the reply is the whole thing. There is no client to
install: the owner API is a Unix socket, and a recipient redeems with curl,
openssl and ssh-keygen.

Send the whole URL, including the part after '#', to the recipient over a
channel you trust. That fragment is the capability; this machine keeps the only
other copy, and the coordination service never sees it.

Automatic updates are not installed.
DONE
