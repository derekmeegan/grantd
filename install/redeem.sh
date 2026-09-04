#!/bin/sh
#
# Redeem a grantd capability URL and open an SSH session.
#
# This is the reference client. It uses curl, openssl, ssh-keygen and
# coreutils only, and follows docs/whitepaper.md. The proof of work at first
# registration uses python3 when present, because a shell loop is slow.
#
# Usage:
#   redeem.sh [URL] [--out DIR] [--identity FILE] [--connect [cmd...]]
#
# The URL can also come from the GRANTD_CAPABILITY variable, or from stdin
# when URL is "-". Other users on the same machine can read command line
# arguments, so prefer those two forms on a shared machine.
set -eu

CAP="${GRANTD_CAPABILITY:-}"
OUT=""
CONNECT=0
IDENTITY="${GRANTD_IDENTITY:-${HOME:-.}/.grantd/agent_identity.pem}"

# ------------------------------------------------------------------ helpers

die()  { echo "redeem.sh: $*" >&2; exit 1; }
note() { echo "$*" >&2; }

usage() {
  sed -n '2,/^set -eu/p' "$0" | sed 's/^# \{0,1\}//;$d' >&2
  exit 2
}

# matches <string> <extended regex>
matches() { printf '%s' "$1" | grep -Eq "$2"; }

# ---------------------------------------------------------------- arguments

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --connect) CONNECT=1; shift; break ;;
    -h|--help) usage ;;
    -) CAP="$(cat)"; shift ;;
    -*) die "unknown flag: $1" ;;
    *) CAP="$1"; shift ;;
  esac
done
[ -n "$CAP" ] || usage

for tool in curl ssh-keygen od sed tr awk grep; do
  command -v "$tool" >/dev/null 2>&1 || die "needs $tool"
done

# ------------------------------------------------------------------ openssl
#
# macOS ships LibreSSL as openssl, and LibreSSL has no Ed25519. It fails
# with "Algorithm ed25519 not found" and still exits 0. So test the
# capability instead of the version string.

find_openssl() {
  for candidate in \
      "${GRANTD_OPENSSL:-}" \
      openssl openssl3 \
      /opt/homebrew/opt/openssl@3/bin/openssl \
      /opt/homebrew/opt/openssl/bin/openssl \
      /usr/local/opt/openssl@3/bin/openssl \
      /opt/local/bin/openssl; do
    [ -n "$candidate" ] || continue
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" genpkey -algorithm ed25519 -out /dev/null >/dev/null 2>&1; then
      printf '%s' "$candidate"; return 0
    fi
  done
  return 1
}

OPENSSL="$(find_openssl)" || die "no OpenSSL with Ed25519 support found.
  openssl on this machine is $(openssl version 2>/dev/null || echo 'missing').
  macOS ships LibreSSL, which cannot do Ed25519. Install OpenSSL 3
  (brew install openssl@3) or set GRANTD_OPENSSL to a capable binary."

# ---------------------------------------------------------------- work dirs

[ -n "$OUT" ] || OUT="$(mktemp -d)"
mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
umask 077

# --------------------------------------------------------------------- http
#
# Every HTTP call goes through here. A bare `curl -sf` under `set -e` exits
# with no message, and an agent with no terminal cannot tell a typo from a
# rate limit.

http() { # http <method> <url> [body file] -> response body on stdout
  _method="$1"; _url="$2"; _bodyfile="${3:-}"
  _out="$WORK/http.out"
  if [ -n "$_bodyfile" ]; then
    _code="$(curl -s -o "$_out" -w '%{http_code}' --connect-timeout 10 --max-time 60 \
      -X "$_method" "$_url" -H 'content-type: application/json' -d "@$_bodyfile")"
  else
    _code="$(curl -s -o "$_out" -w '%{http_code}' --connect-timeout 10 --max-time 60 \
      -X "$_method" "$_url")"
  fi
  _body="$(cat "$_out")"
  case "$_code" in
    2*) printf '%s' "$_body"; return 0 ;;
    000) die "could not reach $_url (connection failed or timed out)" ;;
    429) die "rate limited by $_url. Wait a minute and try again" ;;
    *)
      _err="$(json_str "$_body" code)"
      _msg="$(json_str "$_body" message)"
      [ -z "$_err" ] || die "$_err: ${_msg:-HTTP $_code} (from $_url)"
      die "HTTP $_code from $_url: $(printf '%s' "$_body" | head -c 200)"
      ;;
  esac
}

# ---------------------------------------------------------------- encodings
#
# Canonical bytes are built as hex strings and converted to bytes once at
# the end. Hex stays printable while debugging.
#
# tests/e2e/cbe-vectors.sh evaluates the functions from hexof() up to
# raw_pubkey_hex(). Keep that range free of top-level commands.

hexof()   { printf '%s' "$1" | LC_ALL=C od -An -tx1 -v | tr -d ' \n'; }
hexfile() { od -An -tx1 -v < "$1" | tr -d ' \n'; }
u32()     { printf '%08x' "$1"; }
u64()     { printf '%016x' "$1"; }

# unhex <hex> -> raw bytes on stdout
#
# Two portability traps. dash ignores printf '%b' escapes such as \xHH. GNU
# awk in a UTF-8 locale prints %c as a character, so byte 0xff becomes two
# bytes. LC_ALL=C makes awk print bytes, including NUL.
unhex() {
  printf '%s' "$1" | LC_ALL=C awk '
    BEGIN { A = "0123456789abcdef" }
    {
      for (i = 1; i <= length($0); i += 2)
        printf "%c", (index(A, substr($0, i, 1)) - 1) * 16 + index(A, substr($0, i + 1, 1)) - 1
    }'
}

b64u() { "$OPENSSL" base64 -A | tr '+/' '-_' | tr -d '='; }

# b64u_decode_hex <base64url> -> hex
b64u_decode_hex() {
  _s="$(printf '%s' "$1" | tr '\-_' '+/')"
  _pad=$(( (4 - ${#_s} % 4) % 4 ))
  while [ "$_pad" -gt 0 ]; do _s="${_s}="; _pad=$((_pad - 1)); done
  printf '%s' "$_s" | "$OPENSSL" base64 -d -A | LC_ALL=C od -An -tx1 -v | tr -d ' \n'
}

# json_str <json> <key> and json_num <json> <key> read one flat value. The
# responses are small and this project generates them. The values are still
# validated before use.
json_str() { printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1; }
json_num() { printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\([0-9]\{1,\}\).*/\1/p" | head -1; }

# CBE, docs/whitepaper.md §5.1:
#   CBE(context, fields) = LP(utf8(context)) || u32be(len(fields))
#                          || for each: LP(utf8(name)) || tag || LP(value)
lp()       { printf '%s%s' "$(u32 $(( ${#1} / 2 )))" "$1"; }
f_string() { printf '%s01%s' "$(lp "$(hexof "$1")")" "$(lp "$(hexof "$2")")"; }
f_u64()    { printf '%s02%s' "$(lp "$(hexof "$1")")" "$(lp "$(u64 "$2")")"; }
f_bytes()  { printf '%s03%s' "$(lp "$(hexof "$1")")" "$(lp "$2")"; }

# cbe <context> <field count> <field hex>... -> hex
# The fields are joined without a separator. "$*" would insert spaces.
cbe() {
  _ctx="$1"; _n="$2"; shift 2
  _acc=""
  for _f in "$@"; do _acc="${_acc}${_f}"; done
  printf '%s%s%s' "$(lp "$(hexof "$_ctx")")" "$(u32 "$_n")" "$_acc"
}

# ed25519_sign_hex <private key pem> <hex message> -> base64url signature
ed25519_sign_hex() {
  _msg="$(mktemp)"; unhex "$2" > "$_msg"
  "$OPENSSL" pkeyutl -sign -inkey "$1" -rawin -in "$_msg" | b64u
  rm -f "$_msg"
}

# ed25519_verify_hex <hex public key> <hex message> <hex signature>
ed25519_verify_hex() {
  _der="$(mktemp)"; _msg="$(mktemp)"; _sig="$(mktemp)"
  unhex "302a300506032b6570032100$1" > "$_der"
  unhex "$2" > "$_msg"
  unhex "$3" > "$_sig"
  "$OPENSSL" pkeyutl -verify -pubin -keyform DER -inkey "$_der" -rawin \
    -in "$_msg" -sigfile "$_sig" >/dev/null 2>&1
  _ok=$?
  rm -f "$_der" "$_msg" "$_sig"
  return $_ok
}

# hmac_hex <hex key> <hex message> -> base64url mac
#
# With python3 the key travels in the environment, which other users cannot
# read. Without python3 the key is on the openssl command line.
hmac_hex() {
  _msg="$(mktemp)"; unhex "$2" > "$_msg"
  if command -v python3 >/dev/null 2>&1; then
    HMAC_KEY_HEX="$1" python3 -c '
import hashlib, hmac, os, sys
key = bytes.fromhex(os.environ["HMAC_KEY_HEX"])
msg = open(sys.argv[1], "rb").read()
sys.stdout.buffer.write(hmac.new(key, msg, hashlib.sha256).digest())
' "$_msg" | b64u
  else
    "$OPENSSL" dgst -sha256 -mac HMAC -macopt "hexkey:$1" -binary "$_msg" | b64u
  fi
  rm -f "$_msg"
}

# b32_from_hex <hex> -> RFC 4648 base32, lowercase, no padding
#
# Implemented in awk because base32(1) is GNU only. The accumulator is
# masked after every character so that awk never needs more than 13 bits.
b32_from_hex() {
  printf '%s' "$1" | LC_ALL=C awk '
    BEGIN { A = "abcdefghijklmnopqrstuvwxyz234567"; H = "0123456789abcdef" }
    {
      val = 0; bits = 0; out = ""
      for (i = 1; i <= length($0); i += 2) {
        b = (index(H, substr($0, i, 1)) - 1) * 16 + index(H, substr($0, i + 1, 1)) - 1
        val = val * 256 + b
        bits += 8
        while (bits >= 5) {
          shift = bits - 5
          out = out substr(A, int(val / (2 ^ shift)) % 32 + 1, 1)
          val = val % (2 ^ shift)
          bits = shift
        }
      }
      if (bits > 0) out = out substr(A, (val * (2 ^ (5 - bits))) % 32 + 1, 1)
      print out
    }'
}

# id_of <prefix> <hex public key> -> <prefix>_base32(sha256(key)[0:20])
id_of() {
  _d="$(unhex "$2" | "$OPENSSL" dgst -sha256 -binary | LC_ALL=C od -An -tx1 -v -N 20 | tr -d ' \n')"
  printf '%s_%s' "$1" "$(b32_from_hex "$_d")"
}
agent_id_of() { id_of a "$1"; }
host_id_of()  { id_of h "$1"; }

# raw_pubkey_hex <private key pem> -> 32 raw public key bytes, hex
raw_pubkey_hex() {
  "$OPENSSL" pkey -in "$1" -pubout -outform DER | tail -c 32 | LC_ALL=C od -An -tx1 -v | tr -d ' \n'
}

# ----------------------------------------------------------- capability URL

case "$CAP" in
  *'#'*) ;;
  *) die "the URL has no '#' fragment, so it carries no capability secret" ;;
esac

SECRET_B64="${CAP##*#}"
CAP_PATH="${CAP%%#*}"
GRANT_ID="${CAP_PATH##*/}"
REST="${CAP_PATH%/*}"
HOST_ID="${REST##*/}"
ORIGIN="${REST%/g/*}"

matches "$HOST_ID" '^h_[a-z2-7]{32}$' || die "malformed host id in the URL"
matches "$GRANT_ID" '^g_[a-z2-7]{16}$' || die "malformed grant id in the URL"
matches "$ORIGIN" '^https?://[A-Za-z0-9.:-]+$' || die "malformed origin in the URL"

SECRET_HEX="$(b64u_decode_hex "$SECRET_B64")"
[ "${#SECRET_HEX}" -eq 64 ] || die "the capability secret is not 32 bytes"

note "host:   $HOST_ID"
note "grant:  $GRANT_ID"
note "origin: $ORIGIN"

# ------------------------------------------------------------- host record
#
# The service is not trusted. The host id is a hash of the host identity key,
# so the host's signed registration can be verified with no other trust
# anchor. Hostname, port, user and the SSH CA come from that record.

RECORD="$(http GET "$ORIGIN/v1/hosts/$HOST_ID")"
REG="$(printf '%s' "$RECORD" | sed -n 's/.*"registration"[[:space:]]*:[[:space:]]*{\([^}]*\)}.*/\1/p')"
[ -n "$REG" ] || die "the host record carries no signed registration"

REG_VERSION="$(json_num "$REG" version)"
REG_HOST_ID="$(json_str "$REG" host_id)"
REG_PUB_HEX="$(b64u_decode_hex "$(json_str "$REG" identity_public_key)")"
CA_PUB="$(json_str "$REG" ssh_ca_public_key)"
HOST_KEY="$(json_str "$REG" ssh_host_public_key)"
HOST="$(json_str "$REG" hostname)"
PORT="$(json_num "$REG" ssh_port)"
USER="$(json_str "$REG" ssh_user)"
REG_TS="$(json_num "$REG" timestamp)"
REG_NONCE_HEX="$(b64u_decode_hex "$(json_str "$REG" nonce)")"
REG_SIG_HEX="$(b64u_decode_hex "$(json_str "$RECORD" signature)")"

[ "$REG_VERSION" = 1 ] || die "host registration has protocol version '$REG_VERSION'"
[ "$REG_HOST_ID" = "$HOST_ID" ] || die "host record is for a different host"
[ "$(host_id_of "$REG_PUB_HEX")" = "$HOST_ID" ] || die "host identity key does not match the host id"
matches "$CA_PUB" '^ssh-ed25519 [A-Za-z0-9+/]+=*$' || die "host record carries a malformed SSH CA key"
# The key sshd will present. The CA key is how the host verifies this agent;
# this is how this agent verifies the host. A record without one cannot be
# pinned, and an unpinned connection goes to whatever machine answers.
matches "$HOST_KEY" '^ssh-ed25519 [A-Za-z0-9+/]+=*$' || die "host record carries no usable SSH host key"
[ "$HOST_KEY" != "$CA_PUB" ] || die "host record uses its CA key as its host key"
matches "$HOST" '^[][A-Za-z0-9._:][][A-Za-z0-9._:-]{0,252}$' || die "host record carries a malformed hostname"
matches "$PORT" '^[0-9]{1,5}$' && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "host record carries a bad port"
matches "$USER" '^[a-z_][a-z0-9_-]{0,31}$' || die "host record carries a bad user name"
[ "$USER" != root ] || die "host record names root"

REG_CBE="$(cbe 'grantd/v1/host-register' 10 \
    "$(f_u64    version 1)" \
    "$(f_string host_id "$HOST_ID")" \
    "$(f_bytes  identity_public_key "$REG_PUB_HEX")" \
    "$(f_string ssh_ca_public_key "$CA_PUB")" \
    "$(f_string ssh_host_public_key "$HOST_KEY")" \
    "$(f_string hostname "$HOST")" \
    "$(f_u64    ssh_port "$PORT")" \
    "$(f_string ssh_user "$USER")" \
    "$(f_u64    timestamp "$REG_TS")" \
    "$(f_bytes  nonce "$REG_NONCE_HEX")")"
ed25519_verify_hex "$REG_PUB_HEX" "$REG_CBE" "$REG_SIG_HEX" \
  || die "host registration signature does not verify"

printf '%s\n' "$CA_PUB" > "$WORK/ca.pub"
CA_FP="$(ssh-keygen -lf "$WORK/ca.pub" | awk '{print $2}')"
note "target: $USER@$HOST:$PORT (signed by the host)"

# Pin the host key now, keyed by host id via HostKeyAlias below, so the entry
# does not depend on how the address is spelled or on how the connection is
# carried. StrictHostKeyChecking=yes then makes the wrong machine a refusal.
KNOWN_HOSTS="$OUT/known_hosts"
printf '%s %s\n' "$HOST_ID" "$HOST_KEY" > "$KNOWN_HOSTS"
printf '%s\n' "$HOST_KEY" > "$WORK/hostkey.pub"
HOST_KEY_FP="$(ssh-keygen -lf "$WORK/hostkey.pub" | awk '{print $2}')"
note "pinned: host key $HOST_KEY_FP"

# ---------------------------------------------------------- reachability
#
# A grant is single use. Burning one and then finding that this machine
# cannot open a session wastes it, so check the path to the host first.
#
# The check speaks SSH, and that is the whole point of it. A sandbox gateway
# that inspects the first bytes of a tunnel will carry a TLS handshake and
# reset a plaintext SSH identification string. A probe that spoke TLS — as a
# curl probe does — would call such a path reachable, and the grant would be
# spent before ssh failed. So this reads the server banner, sends an
# identification string of its own, and only then calls the path usable.

PROBE_PY='
import os, socket, sys
from urllib.parse import urlparse
host, port = sys.argv[1], int(sys.argv[2])
proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
np = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
if host in [h.strip() for h in np.split(",") if h.strip()]:
    proxy = ""
try:
    if proxy:
        p = urlparse(proxy if "://" in proxy else "http://" + proxy)
        s = socket.create_connection((p.hostname, p.port or 8080), timeout=10)
        s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (host, port, host, port)).encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            c = s.recv(1)
            if not c:
                sys.exit("the proxy closed the connection during CONNECT")
            resp += c
        line = resp.split(b"\r\n")[0].decode("latin-1")
        if " 200 " not in line:
            sys.exit("the proxy refused a tunnel to %s:%d (%s)" % (host, port, line))
    else:
        s = socket.create_connection((host, port), timeout=10)
    s.settimeout(10)
    banner = s.recv(256)
    if not banner.startswith(b"SSH-"):
        sys.exit("%s:%d answered, but not with an SSH banner" % (host, port))
    s.sendall(b"SSH-2.0-grantd-probe\r\n")
    s.settimeout(3)
    try:
        s.recv(1)
    except socket.timeout:
        pass
    except OSError as e:
        sys.exit("the path carried the banner but not SSH itself (%s)" % e.__class__.__name__)
    s.close()
except SystemExit:
    raise
except Exception as e:
    sys.exit("%s:%d is not reachable from here (%s)" % (host, port, e.__class__.__name__))
'

# probe_ssh HOST PORT -> 0 reachable, 1 unreachable, 2 could not tell
probe_ssh() {
  if command -v python3 >/dev/null 2>&1; then
    PROBE_DETAIL="$(python3 -c "$PROBE_PY" "$1" "$2" 2>&1)" && return 0
    return 1
  fi
  # No python3. nc can answer for a direct path; through a proxy the honest
  # answer is that we cannot tell, because the curl exit codes an open tunnel
  # produces are the same ones a tunnel that rejects non-TLS bytes produces.
  if [ -z "${HTTPS_PROXY:-${https_proxy:-}}" ] && command -v nc >/dev/null 2>&1; then
    nc -z -w 8 "$1" "$2" >/dev/null 2>&1 && return 0
    PROBE_DETAIL="no answer from $1:$2"
    return 1
  fi
  PROBE_DETAIL="there is no python3 here, so the path could not be checked"
  return 2
}

# probe_bridge HOST -> 0 when the host runs a WebSocket bridge on 443.
# Uses the shim's own handshake, so what is tested is what will be used.
probe_bridge() {
  [ -n "$BRIDGE_PROXY" ] || return 1
  BRIDGE_DETAIL="$(python3 "$BRIDGE_PROXY" --probe "wss://$1/ssh" 2>&1)" && return 0
  return 1
}

# fetch_bridge_proxy: puts the shim beside the key material, from the same
# origin that served this script.
fetch_bridge_proxy() {
  command -v python3 >/dev/null 2>&1 || return 1
  _bp="$OUT/bridge-proxy.py"
  curl -fsS --max-time 20 "$ORIGIN/bridge-proxy.py" -o "$_bp" 2>/dev/null || return 1
  BRIDGE_PROXY="$_bp"
  return 0
}

BRIDGE_PROXY=""
TRANSPORT=direct
if [ "${GRANTD_NO_PROBE:-0}" != 1 ]; then
  # set -e would abort on the non-zero return before the fallback below ever
  # ran, so the status is captured rather than left in statement position.
  _probe_rc=0
  probe_ssh "$HOST" "$PORT" || _probe_rc=$?
  if [ "$_probe_rc" -eq 1 ]; then
    # Direct SSH will not work. Before giving up, see whether the host runs
    # the bridge: a sandbox that allows HTTPS usually allows this.
    note "direct ssh to $HOST:$PORT is not available here; looking for a bridge"
    if fetch_bridge_proxy && probe_bridge "$HOST"; then
      TRANSPORT=bridge
      note "bridge:  wss://$HOST/ssh"
    else
      die "this machine cannot reach $HOST:$PORT, so the session could not be opened.
  $PROBE_DETAIL
The grant was NOT spent. It is still valid until it expires.

grantd needs a path to the host. Either raw outbound TCP to the SSH port, an
HTTP CONNECT proxy in HTTPS_PROXY that carries SSH, or the host's WebSocket
bridge on 443.
  If the host listens only on 22, ask its operator to re-run the installer
  with --listen-port 443, which most sandboxes allow.
  If this sandbox allows only HTTP and TLS, ask its operator to run
  install/bridge.sh, which serves the session over a WebSocket on 443.
  Set GRANTD_NO_PROBE=1 to redeem anyway."
    fi
  elif [ "$_probe_rc" -eq 2 ]; then
    note "could not check the path to $HOST:$PORT ($PROBE_DETAIL); continuing"
  fi
fi

# ------------------------------------------------------------------ identity

if [ ! -f "$IDENTITY" ]; then
  mkdir -p "$(dirname "$IDENTITY")"
  "$OPENSSL" genpkey -algorithm ed25519 -out "$IDENTITY" 2>/dev/null
  note "generated a new agent identity at $IDENTITY"
fi
AGENT_PUB_HEX="$(raw_pubkey_hex "$IDENTITY")"
AGENT_ID="$(agent_id_of "$AGENT_PUB_HEX")"
note "agent:  $AGENT_ID"

# -------------------------------------------------------------- registration

# leading_zero_bits <hex digest> <bits>: true if the digest starts with at
# least <bits> zero bits.
leading_zero_bits() {
  _full=$(( $2 / 4 )); _rem=$(( $2 % 4 ))
  _head="$(printf '%s' "$1" | cut -c1-"$_full")"
  [ "$_full" -eq 0 ] || matches "$_head" '^0+$' || return 1
  [ "$_rem" -eq 0 ] && return 0
  _next="$(printf '%s' "$1" | cut -c$((_full + 1)))"
  [ $(( 0x$_next )) -lt $(( 1 << (4 - _rem) )) ]
}

# solve_pow <prefix hex> <difficulty bits> -> nonce
solve_pow() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$1" "$2" <<'PY'
import hashlib, sys
prefix = bytes.fromhex(sys.argv[1]); bits = int(sys.argv[2])
need = bits // 8; rem = bits % 8
i = 0
while True:
    d = hashlib.sha256(prefix + str(i).encode()).digest()
    if d[:need] == b"\0" * need and (rem == 0 or d[need] >> (8 - rem) == 0):
        print(i); break
    i += 1
PY
    return
  fi
  note "no python3; solving the proof of work in shell, which takes a while"
  _i=0
  while :; do
    unhex "$1" > "$WORK/pow"; printf '%s' "$_i" >> "$WORK/pow"
    _digest="$("$OPENSSL" dgst -sha256 -binary "$WORK/pow" | od -An -tx1 -v | tr -d ' \n')"
    if leading_zero_bits "$_digest" "$2"; then printf '%s' "$_i"; return; fi
    _i=$((_i + 1))
  done
}

register() {
  note "registering $AGENT_ID"
  _ch="$(http POST "$ORIGIN/v1/agent-challenges")"
  _ch_id="$(json_str "$_ch" challenge_id)"
  _prefix="$(json_str "$_ch" prefix)"
  _bits="$(json_num "$_ch" difficulty_bits)"
  [ -n "$_ch_id" ] && [ -n "$_prefix" ] && [ -n "$_bits" ] || die "could not start a registration challenge"

  _nonce="$(solve_pow "$(b64u_decode_hex "$_prefix")" "$_bits")"
  _ts="$(date -u +%s)"
  _cbe="$(cbe 'grantd/v1/agent-register' 6 \
      "$(f_u64    version 1)" \
      "$(f_string agent_id "$AGENT_ID")" \
      "$(f_bytes  public_key "$AGENT_PUB_HEX")" \
      "$(f_string challenge_id "$_ch_id")" \
      "$(f_string pow_nonce "$_nonce")" \
      "$(f_u64    timestamp "$_ts")")"
  _sig="$(ed25519_sign_hex "$IDENTITY" "$_cbe")"

  cat > "$WORK/register.json" <<JSON
{"registration":{"version":1,"agent_id":"$AGENT_ID",
 "public_key":"$(unhex "$AGENT_PUB_HEX" | b64u)","challenge_id":"$_ch_id",
 "pow_nonce":"$_nonce","timestamp":$_ts},"signature":"$_sig"}
JSON
  http POST "$ORIGIN/v1/agents" "$WORK/register.json" >/dev/null
  note "registered"
}

if ! curl -sf -o /dev/null --connect-timeout 10 --max-time 30 "$ORIGIN/v1/agents/$AGENT_ID"; then
  register
fi

# ------------------------------------------------------------ ephemeral key
#
# The certificate is issued over this public key, and the proof below covers
# the key. Nobody in the middle can swap it.

rm -f "$OUT/id_ed25519" "$OUT/id_ed25519.pub"
ssh-keygen -q -t ed25519 -N '' -C '' -f "$OUT/id_ed25519"
# The protocol signs exactly two fields. A comment would change the bytes.
SSH_PUB="$(cut -d' ' -f1,2 < "$OUT/id_ed25519.pub")"
KEY_FP="$(ssh-keygen -lf "$OUT/id_ed25519.pub" | awk '{print $2}')"

# --------------------------------------------------------------- redemption
#
# One statement, two proofs: a signature that names the agent, and a MAC
# that proves possession of the capability.

TS="$(date -u +%s)"
NONCE_HEX="$("$OPENSSL" rand -hex 16)"

fields() {
  printf '%s%s%s%s%s%s%s%s' \
    "$(f_u64    version 1)" \
    "$(f_string host_id "$HOST_ID")" \
    "$(f_string grant_id "$GRANT_ID")" \
    "$(f_string agent_id "$AGENT_ID")" \
    "$(f_bytes  agent_public_key "$AGENT_PUB_HEX")" \
    "$(f_string ssh_public_key "$SSH_PUB")" \
    "$(f_u64    timestamp "$TS")" \
    "$(f_bytes  nonce "$NONCE_HEX")"
}
SIG_CBE="$(cbe 'grantd/v1/redemption-agent-sig' 8 "$(fields)")"
MAC_CBE="$(cbe 'grantd/v1/redemption-proof' 8 "$(fields)")"

AGENT_SIG="$(ed25519_sign_hex "$IDENTITY" "$SIG_CBE")"
PROOF="$(hmac_hex "$SECRET_HEX" "$MAC_CBE")"
unset SECRET_HEX

cat > "$WORK/redeem.json" <<JSON
{"payload":{"version":1,"host_id":"$HOST_ID","grant_id":"$GRANT_ID",
 "agent_id":"$AGENT_ID","agent_public_key":"$(unhex "$AGENT_PUB_HEX" | b64u)",
 "ssh_public_key":"$SSH_PUB","timestamp":$TS,
 "nonce":"$(unhex "$NONCE_HEX" | b64u)"},
 "agent_signature":"$AGENT_SIG","proof":"$PROOF"}
JSON

RESP="$(http POST "$ORIGIN/v1/hosts/$HOST_ID/grants/$GRANT_ID/redeem" "$WORK/redeem.json")"

# ------------------------------------------------------- response checks
#
# The response is not signed. Every field must agree with the host's signed
# registration, and the certificate must come from the host's CA.

CERT="$(json_str "$RESP" certificate)"
[ "$(json_str "$RESP" user)" = "$USER" ] || die "response names a user the host did not sign"
[ "$(json_str "$RESP" hostname)" = "$HOST" ] || die "response names a hostname the host did not sign"
[ "$(json_num "$RESP" port)" = "$PORT" ] || die "response names a port the host did not sign"
matches "$CERT" '^ssh-ed25519-cert-v01@openssh\.com [A-Za-z0-9+/]+=*$' || die "response carries no usable certificate"

CERT_FILE="$OUT/id_ed25519-cert.pub"
printf '%s\n' "$CERT" > "$CERT_FILE"
CERT_INFO="$(ssh-keygen -Lf "$CERT_FILE")" || die "the certificate does not parse"

cert_field() { printf '%s\n' "$CERT_INFO" | sed -n "s/^ *$1: *//p" | head -1; }
cert_ca_fp() { cert_field 'Signing CA' | awk '{print $2}'; }
cert_key_fp() { cert_field 'Public key' | awk '{print $2}'; }
cert_principals() { printf '%s\n' "$CERT_INFO" | awk '/^ *Principals:/{f=1;next} f&&/^ *[A-Za-z ]+:/{f=0} f{print $1}'; }

[ "$(cert_ca_fp)" = "$CA_FP" ] || die "the certificate was not signed by the host's CA"
[ "$(cert_key_fp)" = "$KEY_FP" ] || die "the certificate is for a different key"
[ "$(cert_principals)" = "$USER" ] || die "the certificate names principals other than $USER"

echo "$RESP"

# ---------------------------------------------------------------- connect

# The pinned form is the only form this script emits. Without a known_hosts
# entry ssh cannot prompt when there is no terminal and fails, and the reflex
# fix, StrictHostKeyChecking=no, accepts whatever machine answers.
# Over the bridge the transport changes and nothing else does. HostKeyAlias
# is still the host id and the known_hosts entry is still the one written
# above, so the same pin gates the same session; ssh simply talks to a
# WebSocket instead of a socket it opened itself.
if [ "$TRANSPORT" = bridge ]; then
  PROXY_OPT="python3 $BRIDGE_PROXY wss://$HOST/ssh"
fi

if [ "$CONNECT" -eq 1 ]; then
  if [ "$TRANSPORT" = bridge ]; then
    exec ssh -i "$OUT/id_ed25519" \
      -o CertificateFile="$CERT_FILE" \
      -o IdentitiesOnly=yes \
      -o UserKnownHostsFile="$KNOWN_HOSTS" \
      -o StrictHostKeyChecking=yes \
      -o HostKeyAlias="$HOST_ID" \
      -o HostKeyAlgorithms=ssh-ed25519 \
      -o ProxyCommand="$PROXY_OPT" \
      -l "$USER" -p "$PORT" -- "$HOST" "$@"
  fi
  exec ssh -i "$OUT/id_ed25519" \
    -o CertificateFile="$CERT_FILE" \
    -o IdentitiesOnly=yes \
    -o UserKnownHostsFile="$KNOWN_HOSTS" \
    -o StrictHostKeyChecking=yes \
    -o HostKeyAlias="$HOST_ID" \
    -o HostKeyAlgorithms=ssh-ed25519 \
    -l "$USER" -p "$PORT" -- "$HOST" "$@"
fi

if [ "$TRANSPORT" = bridge ]; then
cat >&2 <<EOF

ssh -i '$OUT/id_ed25519' \\
    -o CertificateFile='$CERT_FILE' \\
    -o IdentitiesOnly=yes \\
    -o UserKnownHostsFile='$KNOWN_HOSTS' \\
    -o StrictHostKeyChecking=yes \\
    -o HostKeyAlias=$HOST_ID \\
    -o HostKeyAlgorithms=ssh-ed25519 \\
    -o ProxyCommand='$PROXY_OPT' \\
    -l '$USER' -p $PORT -- '$HOST'

This machine has no raw TCP path to $HOST:$PORT, so the session goes over the
host's WebSocket bridge on 443. TLS there terminates on the host, not on the
coordination service, and the host key pinned in $KNOWN_HOSTS still gates the
session exactly as it would directly. Keep every one of those options.
EOF
else
cat >&2 <<EOF

ssh -i '$OUT/id_ed25519' \\
    -o CertificateFile='$CERT_FILE' \\
    -o IdentitiesOnly=yes \\
    -o UserKnownHostsFile='$KNOWN_HOSTS' \\
    -o StrictHostKeyChecking=yes \\
    -o HostKeyAlias=$HOST_ID \\
    -o HostKeyAlgorithms=ssh-ed25519 \\
    -l '$USER' -p $PORT -- '$HOST'

The host key is pinned in $KNOWN_HOSTS, keyed by host id. Keep those options.
EOF
fi
