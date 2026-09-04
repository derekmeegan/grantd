#!/usr/bin/env bash
#
# grantd 443 bridge — optional, and separate from install.sh on purpose.
#
# It serves an SSH session over a WebSocket on 443, for visiting agents whose
# sandbox has no raw TCP egress. Such a sandbox usually permits HTTPS and
# nothing else, and a gateway there will often carry a TLS handshake but reset
# a plaintext SSH identification string. A WebSocket upgrade is ordinary HTTPS
# to that gateway.
#
# This does not touch sshd, and install.sh's surface is unchanged. It also
# changes nothing about who may open a session: TLS terminates here, on this
# machine, and the visitor still pins this host's key and still presents a
# certificate this host's CA issued. The coordination service is not in the
# path — it never sees a byte of the session.
#
# What it does change: sshd sees every bridged session as coming from
# 127.0.0.1. Source-IP controls (fail2ban, per-source MaxStartups) cannot see
# a bridged visitor. nginx's rate and connection limits below replace them.
set -euo pipefail

CONFDIR=/etc/grantd
LIBDIR=/usr/local/lib/grantd
STATE_DB=/var/lib/grant-signer/state.db
BRIDGE_PORT=8022
BRIDGE_USER=grantdbridge
UNIT=/etc/systemd/system/grantd-bridge.service
NGINX_SITE=/etc/nginx/sites-available/grantd-bridge
WEBROOT=/var/www/grantd-bridge
EMAIL=""
VERSION=""
RELEASES_URL=""
ASSUME_YES=0
STAGING=0

DEFAULT_RELEASE_KEY="$(cat <<'KEY'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC9pwb+PFN4sQGiE1betNWba9+5/4vgXcOU/1zbO0RlD grantd release signing
KEY
)"
RELEASE_KEY=""

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m==> %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31mbridge.sh: %s\033[0m\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<USAGE
grantd 443 bridge

  sudo ./bridge.sh [--email you@example.com] [options]

Options:
  --email ADDRESS      registration address for Let's Encrypt (recommended:
                       it is how you hear about renewal failures)
  --version V          release to take grantd-bridge from (default: latest)
  --releases-url URL   where to fetch artifacts (default: ORIGIN/releases)
  --release-key KEY    ssh-ed25519 key that must have signed the release
  --staging            use Let's Encrypt staging, for rehearsals
  --yes                do not prompt

Requires: this machine already enrolled with install.sh, a DNS name that
resolves here (enroll with --dns-suffix, or point one yourself), and ports 80
and 443 free.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --email) EMAIL="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --releases-url) RELEASES_URL="$2"; shift 2 ;;
    --release-key) RELEASE_KEY="$2"; shift 2 ;;
    --staging) STAGING=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument: $1" ;;
  esac
done
[ -n "$RELEASE_KEY" ] || RELEASE_KEY="$DEFAULT_RELEASE_KEY"

# ------------------------------------------------------------------ preflight

[ "$(id -u)" -eq 0 ] || die "bridge.sh must run as root"
[ -x "$LIBDIR/grant-signer" ] || die "grantd is not installed here; run install.sh first"
command -v systemctl >/dev/null 2>&1 || die "this installer needs systemd"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $ARCH" ;;
esac

log "reading this machine's enrollment"
STATUS="$(runuser -u grantsigner -- "$LIBDIR/grant-signer" status \
            --key-dir "$CONFDIR" --state "$STATE_DB" 2>/dev/null)" \
  || die "could not read the signer state"
read_field() { printf '%s' "$STATUS" | python3 -c "import json,sys;print(json.load(sys.stdin).get('$1',''))"; }
HOSTNAME_ADV="$(read_field hostname)"
HOST_ID="$(read_field host_id)"
SSH_PORT="$(read_field ssh_port)"
ORIGIN="$(read_field origin)"
[ -n "$HOSTNAME_ADV" ] || die "this machine has no advertised hostname"
[ -n "$RELEASES_URL" ] || RELEASES_URL="${ORIGIN%/}/releases"

log "  host id:    $HOST_ID"
log "  advertised: $HOSTNAME_ADV:$SSH_PORT"

# certbot needs a real name that resolves here, not an address.
case "$HOSTNAME_ADV" in
  *[!0-9.]*) ;;
  *) die "this machine advertises a bare address ($HOSTNAME_ADV).
  The bridge needs a DNS name so that a certificate can be issued for it.
  Re-run install.sh with --dns-suffix, or point a name here and use --hostname." ;;
esac

# nginx must own 443. A 443 sshd listener from install.sh --listen-port 443
# would win the bind and the bridge would never start.
if ss -tlnp 2>/dev/null | grep -qE ':443 .*sshd' || [ "$SSH_PORT" = 443 ]; then
  die "sshd is listening on 443 (advertised port is $SSH_PORT).
  nginx needs 443 for the bridge, and the two cannot share it.
  Re-run install.sh without --listen-port 443 so sshd goes back to 22, then
  run this again. Visitors with raw TCP will use 22; visitors without it will
  use the bridge, which is the case --listen-port 443 was working around."
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  printf 'Install nginx and certbot, obtain a certificate for %s, and serve the\nbridge on 443? [y/N] ' "$HOSTNAME_ADV"
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) die "aborted" ;; esac
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ------------------------------------------------------- the bridge binary

CURL=(curl -fsSL --proto '=https' --proto-redir '=https' --max-time 120)

if [ -z "$VERSION" ]; then
  log "resolving the latest release"
  "${CURL[@]}" "$RELEASES_URL/latest.json" -o "$WORK/latest.json" \
    || die "could not fetch $RELEASES_URL/latest.json"
  VERSION="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$WORK/latest.json" | head -1)"
  [ -n "$VERSION" ] || die "could not determine the latest version"
fi

log "downloading grantd-bridge $VERSION (linux/$ARCH)"
for f in "grantd-bridge-linux-$ARCH" VERSION SHA256SUMS SHA256SUMS.sig; do
  "${CURL[@]}" "$RELEASES_URL/$VERSION/$f" -o "$WORK/$f" || die "could not download $f"
done

# Signature first, then hashes: hashes from an unsigned list only prove the
# download was not corrupted. Same order and same key as install.sh.
log "verifying the release signature"
printf 'grantd-release %s\n' "$RELEASE_KEY" > "$WORK/allowed_signers"
ssh-keygen -Y verify -f "$WORK/allowed_signers" -I grantd-release -n grantd-release \
    -s "$WORK/SHA256SUMS.sig" < "$WORK/SHA256SUMS" >/dev/null \
  || die "release signature does not verify; refusing to install"

log "verifying artifact hashes"
: > "$WORK/verify.txt"
for f in "grantd-bridge-linux-$ARCH" VERSION; do
  n="$(grep -cE "^[0-9a-f]{64}  $f\$" "$WORK/SHA256SUMS" || true)"
  [ "$n" -eq 1 ] || die "signed SHA256SUMS lists $f $n times; expected exactly once"
  grep -E "^[0-9a-f]{64}  $f\$" "$WORK/SHA256SUMS" >> "$WORK/verify.txt"
done
( cd "$WORK" && sha256sum -c --strict verify.txt >/dev/null 2>&1 ) \
  || die "artifact hash mismatch; refusing to install"

signed="$(tr -d '[:space:]' < "$WORK/VERSION")"
[ "$signed" = "$VERSION" ] \
  || die "the signed release is $signed but $VERSION was requested; refusing to install"

install -m 0755 -o root -g root "$WORK/grantd-bridge-linux-$ARCH" "$LIBDIR/grantd-bridge"
log "installed $LIBDIR/grantd-bridge"

# ------------------------------------------------------------------ packages

log "installing nginx and certbot"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1 || warn "apt-get update reported a problem; continuing"
apt-get install -y -qq nginx certbot >/dev/null 2>&1 \
  || die "could not install nginx and certbot"

# ------------------------------------------------------------------- service

getent group "$BRIDGE_USER" >/dev/null || groupadd --system "$BRIDGE_USER"
id -u "$BRIDGE_USER" >/dev/null 2>&1 || \
  useradd --system --gid "$BRIDGE_USER" --no-create-home --shell /usr/sbin/nologin "$BRIDGE_USER"

cat > "$UNIT" <<UNITEOF
[Unit]
Description=grantd 443 bridge (WebSocket to local sshd)
Documentation=https://github.com/derekmeegan/grantd
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$BRIDGE_USER
Group=$BRIDGE_USER
ExecStart=$LIBDIR/grantd-bridge --listen 127.0.0.1:$BRIDGE_PORT
Restart=always
RestartSec=2

# The same posture as grantd.service: assume this process is compromised. It
# needs to accept on loopback and open one loopback connection to sshd, and it
# gets nothing else. It never reads /etc/grantd, which holds both private keys.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
InaccessiblePaths=$CONFDIR /var/lib/grant-signer /run/grantd
RestrictAddressFamilies=AF_INET AF_INET6
# It talks to nginx and to sshd, both on this machine, and to nothing else.
IPAddressAllow=127.0.0.0/8
IPAddressDeny=any
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
UNITEOF

systemctl daemon-reload
systemctl enable --now grantd-bridge >/dev/null 2>&1 || die "grantd-bridge did not start"
sleep 1
systemctl is-active --quiet grantd-bridge || die "grantd-bridge is not running; see journalctl -u grantd-bridge"
log "grantd-bridge running on 127.0.0.1:$BRIDGE_PORT"

# ------------------------------------------------------------ certificate

mkdir -p "$WEBROOT/.well-known/acme-challenge"
chown -R www-data:www-data "$WEBROOT"

# Port 80 serves the ACME challenge and nothing else, so that renewal keeps
# working without opening a second surface.
cat > "$NGINX_SITE" <<HTTPEOF
server {
    listen 80;
    listen [::]:80;
    server_name $HOSTNAME_ADV;

    location ^~ /.well-known/acme-challenge/ {
        root $WEBROOT;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}
HTTPEOF
ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/grantd-bridge
rm -f /etc/nginx/sites-enabled/default
nginx -t >/dev/null 2>&1 || die "nginx rejected the port 80 configuration"
systemctl reload nginx 2>/dev/null || systemctl restart nginx

log "obtaining a certificate for $HOSTNAME_ADV"
CERTBOT=(certbot certonly --webroot -w "$WEBROOT" -d "$HOSTNAME_ADV" \
         --non-interactive --agree-tos --keep-until-expiring)
if [ -n "$EMAIL" ]; then CERTBOT+=(-m "$EMAIL"); else CERTBOT+=(--register-unsafely-without-email); fi
[ "$STAGING" -eq 1 ] && CERTBOT+=(--staging)
"${CERTBOT[@]}" >/dev/null 2>&1 \
  || die "certbot could not obtain a certificate for $HOSTNAME_ADV.
  Check that the name resolves to this machine and that port 80 is reachable.
  Run the certbot command by hand to see why:
    ${CERTBOT[*]}"

CERTDIR="/etc/letsencrypt/live/$HOSTNAME_ADV"
[ -f "$CERTDIR/fullchain.pem" ] || die "certbot reported success but $CERTDIR/fullchain.pem is missing"

# ----------------------------------------------------------------- nginx 443

# One location upgrades; everything else is 404. The bridge is not a web
# server and should not look like one.
cat > "$NGINX_SITE" <<TLSEOF
limit_conn_zone \$binary_remote_addr zone=grantd_bridge_conn:10m;
limit_req_zone  \$binary_remote_addr zone=grantd_bridge_req:10m rate=30r/m;

server {
    listen 80;
    listen [::]:80;
    server_name $HOSTNAME_ADV;

    location ^~ /.well-known/acme-challenge/ {
        root $WEBROOT;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name $HOSTNAME_ADV;

    # Deliberately no HTTP/2. A WebSocket upgrade is an HTTP/1.1 mechanism;
    # over HTTP/2 it needs extended CONNECT, which buys nothing here and is
    # one more thing for a sandbox gateway to mishandle.

    ssl_certificate     $CERTDIR/fullchain.pem;
    ssl_certificate_key $CERTDIR/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Address, time and status only. A session's bytes are not logged, and
    # there is nothing in a URL here worth keeping.
    access_log /var/log/nginx/grantd-bridge.access.log combined;

    location = /ssh {
        limit_conn grantd_bridge_conn 8;
        limit_req  zone=grantd_bridge_req burst=10 nodelay;

        proxy_pass http://127.0.0.1:$BRIDGE_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;

        # A session is idle for most of its life. Without this nginx closes
        # an interactive shell after a minute of quiet.
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        proxy_buffering off;
    }

    location / {
        return 404;
    }
}
TLSEOF

nginx -t >/dev/null 2>&1 || die "nginx rejected the bridge configuration; nothing was reloaded"
systemctl reload nginx

# ------------------------------------------------------------------- report

cat <<REPORT

$(log "the bridge is up")

    name:    $HOSTNAME_ADV
    bridge:  wss://$HOSTNAME_ADV/ssh
    sshd:    127.0.0.1:22 (unchanged; the bridge is the only new path)

A visitor whose sandbox has no raw TCP egress will find this automatically:
redeem.sh probes the direct path first and falls back to the bridge.

Two things worth knowing:

  * sshd sees every bridged session as coming from 127.0.0.1. fail2ban and
    per-source limits cannot see a bridged visitor; nginx's limit_conn and
    limit_req above are what bound them now.
  * TLS terminates here, on this machine. The coordination service is still
    not in the path, and the visitor still pins this host's key, so what
    authorises a session has not changed.

Renewal is certbot's timer. Check it with:
    systemctl list-timers | grep certbot
REPORT
