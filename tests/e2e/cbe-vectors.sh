#!/bin/sh
# Check the shell implementation of canonical encoding against the frozen
# vectors in protocol/test-vectors/v1.json.
#
# This is the third independent implementation of CBE (Go, TypeScript, sh).
# It must reproduce the bytes from the spec, not merely interoperate. Two
# implementations can be wrong in the same way and never notice.
#
# It covers both call shapes of cbe(): fields pre-joined into one argument,
# and fields passed separately. A bug that only appears in the second form is
# what slipped through the first time this was written.
#
# Every check runs twice: under the C locale and under a UTF-8 one. This pins
# a specific bug. GNU awk in a UTF-8 locale treats printf "%c" as a
# character, so byte 0xff becomes the two bytes c3 bf. Debian's mawk is
# byte-oriented and hides this. Ubuntu's gawk does not. The script pins
# LC_ALL=C internally, and this is what proves it.
#
# Usage: cbe-vectors.sh <redeem.sh> <v1.json>
set -eu

REDEEM="${1:?usage: cbe-vectors.sh <redeem.sh> <v1.json>}"
VECTORS="${2:?usage: cbe-vectors.sh <redeem.sh> <v1.json>}"

# Pull the helpers out of the shipped script, so this checks the real thing
# and not a copy that can drift. The range stops before the capability-URL
# parsing, which expects arguments this test does not supply.
#
# The OpenSSL selection comes along too. On macOS the default `openssl` is
# LibreSSL and cannot do Ed25519, so a check that used it tests a different
# binary than the script does.
eval "$(sed -n '/^find_openssl()/,/^}/p' "$REDEEM")"
OPENSSL="$(find_openssl)" || { echo "no Ed25519-capable OpenSSL found" >&2; exit 1; }
eval "$(sed -n '/^hexof()/,/^raw_pubkey_hex()/p' "$REDEEM" | sed '$d')"

vec() { jq -r --arg c "$1" --arg f "$2" '.vectors[] | select(.context == $c) | .[$f]' "$VECTORS"; }
key() { jq -r --arg k "$1" '.keys[$k]' "$VECTORS"; }
id()  { jq -r --arg k "$1" '.identifiers[$k]' "$VECTORS"; }
ssh_key() { jq -r '.ssh_keys.agent_ssh_public_key' "$VECTORS"; }

fail=0
say() { printf '  %s %s\n' "$1" "$2"; }
check() { # check DESCRIPTION GOT WANT
  if [ "$2" = "$3" ]; then say ok "$1 [$LOCALE_LABEL]"; else
    say FAIL "$1 [$LOCALE_LABEL]"; printf '     got:  %s\n     want: %s\n' "$2" "$3"; fail=1
  fi
}

run_checks() {

HOST="$(id host_id)"; GRANT="$(id grant_id)"; AGENT="$(id agent_id)"
APK="$(key agent_identity_pub_hex)"; SECRET="$(key grant_secret_hex)"
SSHPUB="$(ssh_key)"
NONCE=000102030405060708090a0b0c0d0e0f

# --- redemption proof: all eight fields pre-joined into a single argument
fields() {
  printf '%s%s%s%s%s%s%s%s' \
    "$(f_u64 version 1)" \
    "$(f_string host_id "$HOST")" \
    "$(f_string grant_id "$GRANT")" \
    "$(f_string agent_id "$AGENT")" \
    "$(f_bytes agent_public_key "$APK")" \
    "$(f_string ssh_public_key "$SSHPUB")" \
    "$(f_u64 timestamp 1756598460)" \
    "$(f_bytes nonce "$NONCE")"
}
GOT="$(cbe 'grantd/v1/redemption-proof' 8 "$(fields)")"
check "redemption proof bytes (one joined argument)" \
  "$GOT" "$(vec grantd/v1/redemption-proof canonical_hex)"

tmp="$(mktemp)"; unhex "$GOT" > "$tmp"
MAC="$("$OPENSSL" dgst -sha256 -mac HMAC -macopt "hexkey:$SECRET" -binary "$tmp" \
       | od -An -tx1 -v | tr -d ' \n')"
rm -f "$tmp"
check "HMAC over those bytes" "$MAC" "$(vec grantd/v1/redemption-proof mac_hex)"

# --- agent registration: six fields passed as separate arguments
GOT_REG="$(cbe 'grantd/v1/agent-register' 6 \
  "$(f_u64 version 1)" \
  "$(f_string agent_id "$AGENT")" \
  "$(f_bytes public_key "$APK")" \
  "$(f_string challenge_id c_0123456789abcdef)" \
  "$(f_string pow_nonce 31337)" \
  "$(f_u64 timestamp 1756598400)")"
check "agent registration bytes (separate arguments)" \
  "$GOT_REG" "$(vec grantd/v1/agent-register canonical_hex)"

# --- identifier derivation
DERIVED="$(agent_id_of "$APK")"
check "agent_id derivation" "$DERIVED" "$AGENT"

}

# Under C, and under a UTF-8 locale that exposes a character-oriented awk.
LOCALE_LABEL="C"
LC_ALL=C run_checks

UTF8="$(locale -a 2>/dev/null | grep -iE 'C\.utf-?8|en_US\.utf-?8' | head -1)"
if [ -n "$UTF8" ]; then
  LOCALE_LABEL="$UTF8"
  LC_ALL="$UTF8" LANG="$UTF8" run_checks
else
  printf '  skip no UTF-8 locale available to test against\n'
fi

exit $fail
