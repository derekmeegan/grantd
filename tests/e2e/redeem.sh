#!/bin/sh
#
# Redeem a grantd capability URL and open an SSH session.
#
# This is a reference implementation, and its real job is to be evidence: the
# protocol needs no SDK and no grantd-specific client. Everything here is curl,
# openssl, ssh-keygen and coreutils, working from protocol/v1.md alone. If this
# script ever needs something exotic, the protocol has drifted somewhere it
# should not have.
#
# One honest exception, called out where it happens: the registration proof of
# work wants a real interpreter. A shell loop manages a few hundred hashes a
# second, and 20 bits needs about a million of them. That is the proof of work
# doing its job — the cost is the point — but it does mean the one-time
# registration reaches for python3 when it can.
#
# POSIX sh on purpose. An agent that has to install bash to redeem a capability
# is an agent that has been handed an SDK by another name.
#
# Usage:
#   redeem.sh 'https://…/g/<host_id>/<grant_id>#<secret>' [--out DIR] [--connect [cmd…]]
set -eu

CAP=""
OUT=""
CONNECT=0
IDENTITY="${GRANTD_IDENTITY:-${HOME:-.}/.grantd/agent_identity.pem}"

usage() {
  sed -n '2,/^set -eu/p' "$0" | sed 's/^# \{0,1\}//;$d' >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --connect) CONNECT=1; shift; break ;;
    -h|--help) usage ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) CAP="$1"; shift ;;
  esac
done
[ -n "$CAP" ] || usage

for tool in curl ssh-keygen od sed tr awk; do
  command -v "$tool" >/dev/null 2>&1 || { echo "redeem.sh needs $tool" >&2; exit 1; }
done

die() { echo "redeem.sh: $*" >&2; exit 1; }

# Find an OpenSSL that can actually do Ed25519.
#
# macOS ships LibreSSL as `openssl`, and LibreSSL has no Ed25519 at all: it
# fails with "Algorithm ed25519 not found" while still exiting 0, so a naive
# `command -v openssl` check passes and the script dies later with no
# explanation. Every Linux distro ships OpenSSL 3.x, which is why this only
# shows up on a laptop — and a laptop is exactly where a visiting agent runs.
#
# The capability is tested rather than the version string parsed, because that
# is the thing actually needed.
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
  macOS ships LibreSSL, which cannot do Ed25519 — install OpenSSL 3
  (brew install openssl@3) or set GRANTD_OPENSSL to a capable binary."

# Every HTTP call goes through this. `set -e` plus `curl -sf` would otherwise
# exit with no output at all, which is the worst possible failure mode for a
# script whose caller is often an agent with no terminal to inspect: a rate
# limit and a typo in the URL would look identical, and both would look like
# nothing happening.
http() { # http <method> <url> [body] -> body on stdout, status on fd 3
  _m="$1"; _u="$2"; _b="${3:-}"
  _out="$(mktemp)"
  if [ -n "$_b" ]; then
    _code="$(curl -s -o "$_out" -w '%{http_code}' --connect-timeout 10 --max-time 60 \
      -X "$_m" "$_u" -H 'content-type: application/json' -d "$_b")"
  else
    _code="$(curl -s -o "$_out" -w '%{http_code}' --connect-timeout 10 --max-time 60 \
      -X "$_m" "$_u")"
  fi
  _body="$(cat "$_out")"; rm -f "$_out"
  case "$_code" in
    2*) printf '%s' "$_body"; return 0 ;;
    000) die "could not reach $_u (connection failed or timed out)" ;;
    429) die "rate limited by $_u — wait a minute and try again" ;;
    *)
      _err="$(printf '%s' "$_body" | sed -n 's/.*"code"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
      _msg="$(printf '%s' "$_body" | sed -n 's/.*"message"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
      if [ -n "$_err" ]; then die "$_err: ${_msg:-HTTP $_code} (from $_u)"; fi
      die "HTTP $_code from $_u: $(printf '%s' "$_body" | head -c 200)"
      ;;
  esac
}

[ -n "$OUT" ] || OUT="$(mktemp -d)"
mkdir -p "$OUT"

# ------------------------------------------------------------------ encodings
#
# Canonical bytes are assembled as a hex string and converted once at the end.
# Hex is easier to get right in shell than raw bytes, and it keeps every
# intermediate value printable while debugging.

hexof()  { printf '%s' "$1" | LC_ALL=C od -An -tx1 -v | tr -d ' \n'; }
hexfile(){ od -An -tx1 -v < "$1" | tr -d ' \n'; }
u32()    { printf '%08x' "$1"; }
u64()    { printf '%016x' "$1"; }
# hex -> raw bytes.
#
# Two portability traps live in this one function, and both corrupt signatures
# silently rather than failing:
#
#   printf '%b' with \xHH would be the obvious implementation, but dash ignores
#   those escapes entirely and emits the literal text "\x00\x00...". Any bash
#   test of this passes while every real /bin/sh run produces garbage.
#
#   LC_ALL=C is not decoration. GNU awk in a UTF-8 locale treats printf "%c" as
#   a *character*, so byte 0xff becomes the two bytes c3 bf. Every key, nonce
#   and canonical encoding containing a high byte comes out longer and wrong.
#   Debian's mawk happens to be byte-oriented, so this is invisible there and
#   breaks on Ubuntu, which is the more common target.
#
# awk's %c also emits NUL correctly, which matters because canonical bytes are
# full of them — every length prefix starts with three.
unhex() {
  printf '%s' "$1" | LC_ALL=C awk '
    BEGIN { A = "0123456789abcdef" }
    {
      for (i = 1; i <= length($0); i += 2)
        printf "%c", (index(A, substr($0, i, 1)) - 1) * 16 + index(A, substr($0, i + 1, 1)) - 1
    }'
}

b64u()   { "$OPENSSL" base64 -A | tr '+/' '-_' | tr -d '='; }
b64u_decode_hex() {
  # base64url -> hex, restoring the padding the encoding drops.
  # LC_ALL=C throughout: every tool here handles bytes, not text.
  _s="$(printf '%s' "$1" | tr '\-_' '+/')"
  _pad=$(( (4 - ${#_s} % 4) % 4 ))
  while [ "$_pad" -gt 0 ]; do _s="${_s}="; _pad=$((_pad - 1)); done
  printf '%s' "$_s" | "$OPENSSL" base64 -d -A | LC_ALL=C od -An -tx1 -v | tr -d ' \n'
}

# Pull one string or number out of a JSON object. Deliberately not a JSON
# parser: these responses are small, flat, and generated by this project.
json_str() { printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1; }
json_num() { printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\([0-9]\{1,\}\).*/\1/p" | head -1; }

# ------------------------------------------------------------------------ CBE
#
# protocol/v1.md §1:
#   CBE(context, fields) = LP(utf8(context)) || u32be(len(fields))
#                          || for each: LP(utf8(name)) || tag || LP(value)

lp()      { printf '%s%s' "$(u32 $(( ${#1} / 2 )))" "$1"; }
f_string(){ printf '%s01%s' "$(lp "$(hexof "$1")")" "$(lp "$(hexof "$2")")"; }
f_u64()   { printf '%s02%s' "$(lp "$(hexof "$1")")" "$(lp "$(u64 "$2")")"; }
f_bytes() { printf '%s03%s' "$(lp "$(hexof "$1")")" "$(lp "$2")"; }
# Fields are concatenated explicitly. "$*" would join them with a space, which
# is invisible in a hex string and produces canonical bytes that differ from
# every other implementation — the exact class of bug CBE exists to prevent.
cbe() {
  _ctx="$1"; _n="$2"; shift 2
  _acc=""
  for _f in "$@"; do _acc="${_acc}${_f}"; done
  printf '%s%s%s' "$(lp "$(hexof "$_ctx")")" "$(u32 "$_n")" "$_acc"
}

# --------------------------------------------------------------------- crypto

ed25519_sign_hex() { # <pem> <hex message> -> base64url signature
  _tmp="$(mktemp)"; unhex "$2" > "$_tmp"
  "$OPENSSL" pkeyutl -sign -inkey "$1" -rawin -in "$_tmp" | b64u
  rm -f "$_tmp"
}

hmac_hex() { # <hex key> <hex message> -> base64url mac
  _tmp="$(mktemp)"; unhex "$2" > "$_tmp"
  "$OPENSSL" dgst -sha256 -mac HMAC -macopt "hexkey:$1" -binary "$_tmp" | b64u
  rm -f "$_tmp"
}

# base32, RFC 4648, lowercase, no padding — implemented here rather than shelled
# out to base32(1), which is GNU coreutils and absent on macOS and the BSDs. A
# visiting agent is often on a laptop, and "install coreutils first" is exactly
# the kind of dependency this script exists to avoid.
#
# It consumes hex so no binary crosses a pipe, and it masks the accumulator after
# every emitted character so the running value stays under 2^7 instead of growing
# to a 160-bit number awk would render as a float.
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

# agent_id = "a_" || base32(sha256(pub)[0:20])
agent_id_of() {
  _d="$(unhex "$1" | "$OPENSSL" dgst -sha256 -binary | LC_ALL=C od -An -tx1 -v -N 20 | tr -d ' \n')"
  printf 'a_%s' "$(b32_from_hex "$_d")"
}

raw_pubkey_hex() { # <pem> -> 32 raw ed25519 public key bytes, hex
  "$OPENSSL" pkey -in "$1" -pubout -outform DER | tail -c 32 | LC_ALL=C od -An -tx1 -v | tr -d ' \n'
}

# --------------------------------------------------------------- capability URL

case "$CAP" in
  *'#'*) ;;
  *) echo "that URL has no '#' fragment, so it carries no capability secret" >&2; exit 1 ;;
esac

SECRET_B64="${CAP##*#}"
CAP_PATH="${CAP%%#*}"
GRANT_ID="${CAP_PATH##*/}"
REST="${CAP_PATH%/*}"
HOST_ID="${REST##*/}"
ORIGIN="${REST%/g/*}"

SECRET_HEX="$(b64u_decode_hex "$SECRET_B64")"
[ "${#SECRET_HEX}" -eq 64 ] || { echo "the capability secret is not 32 bytes" >&2; exit 1; }

echo "host:   $HOST_ID" >&2
echo "grant:  $GRANT_ID" >&2
echo "origin: $ORIGIN" >&2

# ------------------------------------------------------------------- identity

if [ ! -f "$IDENTITY" ]; then
  mkdir -p "$(dirname "$IDENTITY")"
  ( umask 077; "$OPENSSL" genpkey -algorithm ed25519 -out "$IDENTITY" 2>/dev/null )
  echo "generated a new agent identity at $IDENTITY" >&2
fi
AGENT_PUB_HEX="$(raw_pubkey_hex "$IDENTITY")"
AGENT_ID="$(agent_id_of "$AGENT_PUB_HEX")"
echo "agent:  $AGENT_ID" >&2

# ---------------------------------------------------------------- registration

solve_pow() { # <prefix hex> <difficulty bits> -> nonce
  prefix_hex="$1"; bits="$2"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$prefix_hex" "$bits" <<'PY'
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
  # Shell fallback. Correct, and slow enough that you will notice: a few hundred
  # hashes a second against a target that expects about a million. That is the
  # proof of work working as intended, not a bug.
  echo "no python3; solving the proof of work in shell, which will take a while" >&2
  i=0
  tmp="$(mktemp)"
  zeros="$(printf '0%.0s' $(seq 1 $(( bits / 4 ))))"
  while :; do
    unhex "$prefix_hex" > "$tmp"; printf '%s' "$i" >> "$tmp"
    digest="$("$OPENSSL" dgst -sha256 -binary "$tmp" | od -An -tx1 -v | tr -d ' \n')"
    case "$digest" in "$zeros"*) printf '%s' "$i"; rm -f "$tmp"; return ;; esac
    i=$((i + 1))
  done
}

if ! curl -sf -o /dev/null --connect-timeout 10 --max-time 30 "$ORIGIN/v1/agents/$AGENT_ID"; then
  echo "registering $AGENT_ID" >&2
  CH="$(http POST "$ORIGIN/v1/agent-challenges")"
  CH_ID="$(json_str "$CH" challenge_id)"
  POW_PREFIX="$(json_str "$CH" prefix)"
  POW_BITS="$(json_num "$CH" difficulty_bits)"
  [ -n "$CH_ID" ] || { echo "could not start a registration challenge" >&2; exit 1; }

  POW_NONCE="$(solve_pow "$(b64u_decode_hex "$POW_PREFIX")" "$POW_BITS")"
  TS="$(date -u +%s)"

  REG_CBE="$(cbe 'grantd/v1/agent-register' 6 \
      "$(f_u64   version 1)" \
      "$(f_string agent_id "$AGENT_ID")" \
      "$(f_bytes  public_key "$AGENT_PUB_HEX")" \
      "$(f_string challenge_id "$CH_ID")" \
      "$(f_string pow_nonce "$POW_NONCE")" \
      "$(f_u64   timestamp "$TS")")"
  REG_SIG="$(ed25519_sign_hex "$IDENTITY" "$REG_CBE")"

  REG_BODY="$(cat <<JSON
{"registration":{"version":1,"agent_id":"$AGENT_ID",
 "public_key":"$(unhex "$AGENT_PUB_HEX" | b64u)","challenge_id":"$CH_ID",
 "pow_nonce":"$POW_NONCE","timestamp":$TS},"signature":"$REG_SIG"}
JSON
)"
  http POST "$ORIGIN/v1/agents" "$REG_BODY" >/dev/null
  echo "registered" >&2
fi

# ------------------------------------------------------------- ephemeral key
#
# Generated here and never transmitted. The certificate is issued over its
# public half, and that public half is covered by the proof below, so nobody in
# the middle can swap it.

rm -f "$OUT/id_ed25519" "$OUT/id_ed25519.pub"
ssh-keygen -q -t ed25519 -N '' -C '' -f "$OUT/id_ed25519"
# Exactly two whitespace-separated fields: the protocol signs this string
# verbatim, so a comment or trailing space would change what is authenticated.
SSH_PUB="$(cut -d' ' -f1,2 < "$OUT/id_ed25519.pub")"

# ------------------------------------------------------------------ redemption

TS="$(date -u +%s)"
NONCE_HEX="$("$OPENSSL" rand -hex 16)"

# The same eight fields under two different contexts. One statement, two
# independent proofs: a signature that says which agent is asking, and a MAC
# that proves possession of the capability.
fields() {
  printf '%s%s%s%s%s%s%s%s' \
    "$(f_u64   version 1)" \
    "$(f_string host_id "$HOST_ID")" \
    "$(f_string grant_id "$GRANT_ID")" \
    "$(f_string agent_id "$AGENT_ID")" \
    "$(f_bytes  agent_public_key "$AGENT_PUB_HEX")" \
    "$(f_string ssh_public_key "$SSH_PUB")" \
    "$(f_u64   timestamp "$TS")" \
    "$(f_bytes  nonce "$NONCE_HEX")"
}
SIG_CBE="$(cbe 'grantd/v1/redemption-agent-sig' 8 "$(fields)")"
MAC_CBE="$(cbe 'grantd/v1/redemption-proof' 8 "$(fields)")"

AGENT_SIG="$(ed25519_sign_hex "$IDENTITY" "$SIG_CBE")"
PROOF="$(hmac_hex "$SECRET_HEX" "$MAC_CBE")"

BODY="$(cat <<JSON
{"payload":{"version":1,"host_id":"$HOST_ID","grant_id":"$GRANT_ID",
 "agent_id":"$AGENT_ID","agent_public_key":"$(unhex "$AGENT_PUB_HEX" | b64u)",
 "ssh_public_key":"$SSH_PUB","timestamp":$TS,
 "nonce":"$(unhex "$NONCE_HEX" | b64u)"},
 "agent_signature":"$AGENT_SIG","proof":"$PROOF"}
JSON
)"

RESP="$(http POST "$ORIGIN/v1/hosts/$HOST_ID/grants/$GRANT_ID/redeem" "$BODY")"

# The certificate is the only thing worth extracting; everything else in the
# response is connection detail.
CERT="$(json_str "$RESP" certificate)"
USER="$(json_str "$RESP" user)"
HOSTNAME="$(json_str "$RESP" hostname)"
PORT="$(json_num "$RESP" port)"
printf '%s\n' "$CERT" > "$OUT/id_ed25519-cert.pub"

echo "$RESP"

if [ "$CONNECT" -eq 1 ]; then
  exec ssh -i "$OUT/id_ed25519" \
    -o CertificateFile="$OUT/id_ed25519-cert.pub" \
    -o IdentitiesOnly=yes \
    -p "$PORT" "$USER@$HOSTNAME" "$@"
fi

cat >&2 <<EOF

ssh -i $OUT/id_ed25519 \\
    -o CertificateFile=$OUT/id_ed25519-cert.pub \\
    -o IdentitiesOnly=yes \\
    -p $PORT $USER@$HOSTNAME
EOF
