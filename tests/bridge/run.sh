#!/usr/bin/env bash
#
# The bridge carries an SSH transport byte for byte.
#
# Runs the real grantd-bridge and the real install/bridge-proxy.py against a
# stub sshd, with a TLS front standing in for nginx. No network and no host:
# this is the contract between the two halves, which is what breaks silently
# if either is changed alone.
#
# The bridged bytes are an SSH transport. A frame boundary in the wrong place,
# a helpful newline translation, or a dropped high byte would each produce a
# session that negotiates and then fails, so the assertion is byte equality.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

command -v go >/dev/null 2>&1 || { echo "ok   bridge (skipped: no go toolchain)"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "ok   bridge (skipped: no openssl)"; exit 0; }

openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
  -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

python3 "$REPO/tests/bridge/harness.py" "$REPO" "$WORK"
