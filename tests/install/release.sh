#!/usr/bin/env bash
#
# Install from a real published release, not from local binaries.
#
# This is the path a user takes. Every other test passes --local-dir, which
# skips the download. This suite exercises the code that decides whether to
# trust a binary, so the important assertions are the negative ones: a
# tampered artifact and a release signed by the wrong key must both be refused.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ORIGIN="${GRANTD_TEST_ORIGIN:-https://grantd.derekmeegan.workers.dev}"
# Pinned rather than tracking latest, so a failure here is unambiguous: it means
# this release broke, not that someone published a new one mid-run. Bump it when
# you cut a release.
VERSION="${GRANTD_TEST_VERSION:-v0.2.0}"
PLATFORM="${GRANTD_TEST_PLATFORM:-}"
CONTAINER=grantd-release-test
IMAGE=grantd-install-test

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
# Skips are printed and counted, never folded into the pass total.
skip() { SKIP=$((SKIP+1)); printf '  \033[33mskip\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
dsh()  { docker exec "$CONTAINER" bash -c "$1"; }

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# bash 3.2 (macOS) treats an empty array as unset under `set -u`, so this is
# a plain string, not an array.
#
# The image is tagged per platform. Under emulation the base image differs,
# and one tag across architectures silently runs the wrong binaries.
PLATFORM_ARGS=""
if [ -n "$PLATFORM" ]; then
  PLATFORM_ARGS="--platform $PLATFORM"
  IMAGE="${IMAGE}-$(printf '%s' "$PLATFORM" | tr '/' '-')"
fi

# Build the image every run. A stale image silently drops tools the tests need.
docker build -q $PLATFORM_ARGS -t "$IMAGE" "$REPO/tests/install" >/dev/null

step "booting a systemd machine ${PLATFORM:+($PLATFORM)}"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" $PLATFORM_ARGS --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v "$REPO/install:/opt/grantd-install:ro" \
  "$IMAGE" >/dev/null
for _ in $(seq 1 90); do
  dsh 'systemctl is-system-running 2>/dev/null | grep -qE "running|degraded"' && break
  sleep 1
done
# Under emulation systemd reports "running" before namespace setup works, and
# a unit with PrivateNetwork= then fails with 225/NETWORK. Wait for the
# capability itself.
for _ in $(seq 1 60); do
  dsh 'systemd-run --quiet --pipe --property=PrivateNetwork=yes /bin/true' >/dev/null 2>&1 && break
  sleep 1
done
ok "systemd up ($(dsh 'uname -m' | tr -d '\r\n'))"

# ------------------------------------------------ a tampered release is refused

step "a tampered artifact is refused"
# Serve a doctored copy of the release locally: real signature, real
# SHA256SUMS, real VERSION, one binary swapped. The signature still verifies,
# because it covers the hash list and not the files. Only the per-artifact
# hash check can catch this.
dsh "mkdir -p /srv/$VERSION && cd /srv/$VERSION && \
     for f in grantd-linux-\$(dpkg --print-architecture) grant-signer-linux-\$(dpkg --print-architecture) VERSION SHA256SUMS SHA256SUMS.sig; do
       curl -fsSL '$ORIGIN/releases/$VERSION/'\$f -o \$f; done && \
     echo '{\"version\":\"$VERSION\"}' > /srv/latest.json"
dsh "printf 'not a real binary' > /srv/$VERSION/grantd-linux-\$(dpkg --print-architecture)"
# Detached, so it outlives the exec session that started it. A backgrounded
# process inside `docker exec` dies with that session.
docker exec -d "$CONTAINER" python3 -m http.server 8099 --directory /srv
for _ in $(seq 1 20); do
  dsh 'curl -sf -o /dev/null http://127.0.0.1:8099/latest.json' && break
  sleep 0.5
done
dsh 'curl -sf -o /dev/null http://127.0.0.1:8099/latest.json' \
  || { echo "local release server never came up" >&2; exit 1; }

if dsh "/opt/grantd-install/install.sh --yes --origin $ORIGIN \
        --releases-url http://127.0.0.1:8099 --version $VERSION \
        --ssh-user ubuntu --hostname 127.0.0.1" >/tmp/tamper.log 2>&1; then
  bad "a tampered binary was installed"
else
  grep -qi "hash mismatch" /tmp/tamper.log \
    && ok "tampered artifact rejected on hash mismatch" \
    || { bad "refused for the wrong reason"; tail -3 /tmp/tamper.log; }
fi
dsh 'test ! -e /etc/ssh/sshd_config.d/60-grantd.conf' \
  && ok "nothing was left behind on the rejected install" \
  || bad "a partial install survived"

step "a release signed by the wrong key is refused"
# Re-sign the untampered hash list with an attacker key. This is the case that
# matters when the release bucket is compromised but the signing key is not.
# Remove the signature first: ssh-keygen -Y sign prompts before overwriting,
# and with no TTY it declines silently and leaves the genuine signature in
# place.
dsh "cd /srv/$VERSION && curl -fsSL '$ORIGIN/releases/$VERSION/grantd-linux-'\$(dpkg --print-architecture) -o grantd-linux-\$(dpkg --print-architecture) && \
     rm -f SHA256SUMS.sig && \
     ssh-keygen -q -t ed25519 -N '' -f /tmp/evil -C evil && \
     ssh-keygen -Y sign -f /tmp/evil -n grantd-release SHA256SUMS >/dev/null 2>&1 && \
     test -f SHA256SUMS.sig"
# The signature must be the attacker's, or the next assertion proves nothing.
dsh "cd /srv/$VERSION && printf 'grantd-release %s\n' \"\$(ssh-keygen -y -f /tmp/evil)\" > /tmp/evil_allowed && \
     ssh-keygen -Y verify -f /tmp/evil_allowed -I grantd-release -n grantd-release \
       -s SHA256SUMS.sig < SHA256SUMS >/dev/null" \
  && ok "the release under test really is signed by the attacker key" \
  || bad "could not substitute the signature; the next assertion would be meaningless"
if dsh "/opt/grantd-install/install.sh --yes --origin $ORIGIN \
        --releases-url http://127.0.0.1:8099 --version $VERSION \
        --ssh-user ubuntu --hostname 127.0.0.1" >/tmp/evil.log 2>&1; then
  bad "a release signed by an unknown key was installed"
else
  grep -qi "signature does not verify" /tmp/evil.log \
    && ok "release signed by an unknown key rejected" \
    || { bad "refused for the wrong reason"; tail -3 /tmp/evil.log; }
fi

step "a release served under the wrong version path is refused"
# Restore the genuine signature, then serve the same release as a different
# version. The signed VERSION file does not match the request.
dsh "cd /srv/$VERSION && curl -fsSL '$ORIGIN/releases/$VERSION/SHA256SUMS.sig' -o SHA256SUMS.sig && \
     mkdir -p /srv/v9.9.9 && cp /srv/$VERSION/* /srv/v9.9.9/"
if dsh "/opt/grantd-install/install.sh --yes --origin $ORIGIN \
        --releases-url http://127.0.0.1:8099 --version v9.9.9 \
        --ssh-user ubuntu --hostname 127.0.0.1" >/tmp/downgrade.log 2>&1; then
  bad "a release was installed under a version it was not signed as"
else
  grep -q "signed release is $VERSION but v9.9.9 was requested" /tmp/downgrade.log \
    && ok "release under the wrong version path rejected" \
    || { bad "refused for the wrong reason"; tail -3 /tmp/downgrade.log; }
fi

# ------------------------------------------------------- the genuine release

# Under qemu emulation, this unit's private network namespace fails with EIO,
# so the trust root cannot start with its real sandbox. The binaries are
# unaffected. The sandbox is untested there and is reported as skipped.
EMULATED=0
if [ -n "$PLATFORM" ] && [ "$(docker version --format '{{.Server.Arch}}')" != "$(printf '%s' "$PLATFORM" | cut -d/ -f2)" ]; then
  EMULATED=1
  dsh 'mkdir -p /etc/systemd/system/grant-signer.service.d && \
       printf "[Service]\nPrivateNetwork=no\n" > /etc/systemd/system/grant-signer.service.d/emulation.conf'
  skip "signer network isolation (qemu cannot create the namespace; needs real $PLATFORM hardware)"
fi

step "installing the genuine published release over the network"
if dsh "/opt/grantd-install/install.sh --yes --origin $ORIGIN --version $VERSION \
        --ssh-user ubuntu --hostname 127.0.0.1" >/tmp/rel.log 2>&1; then
  ok "installed from $ORIGIN/releases/$VERSION"
else
  bad "install from the published release failed"; tail -20 /tmp/rel.log
fi
grep -q "verifying the release signature" /tmp/rel.log && ok "signature was verified during install" \
  || bad "install did not report verifying the signature"
grep -q "verifying artifact hashes" /tmp/rel.log && ok "artifact hashes were verified during install" \
  || bad "install did not report verifying hashes"
grep -q "release $VERSION is signed and complete" /tmp/rel.log && ok "signed VERSION matched the request" \
  || bad "install did not report checking the signed version"

dsh 'systemctl is-active grant-signer.service >/dev/null' && ok "signer running from the downloaded binary" \
  || bad "signer not running"
dsh 'systemctl is-active grantd.service >/dev/null' && ok "daemon running from the downloaded binary" \
  || bad "daemon not running"

step "end to end on the downloaded build"
URL=$(docker exec -u ubuntu "$CONTAINER" sh -c \
  "curl -s --unix-socket /run/grantd/owner/owner.sock -X POST http://localhost/grants \
     -H 'content-type: application/json' -d '{\"ttl_seconds\":600}' \
   | sed -n 's/.*\"capability_url\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p'" || true)
case "$URL" in http*) ok "minted a capability" ;; *) bad "mint failed: $URL" ;; esac

if [ -n "$URL" ]; then
  sleep 4
  docker exec -u ubuntu "$CONTAINER" sh -c \
    "GRANTD_IDENTITY=/tmp/v/id.pem sh /opt/grantd-install/redeem.sh --out /tmp/v '$URL'" \
    >/tmp/rel-redeem.log 2>&1 \
    && ok "redeemed" || { bad "redeem failed"; tail -4 /tmp/rel-redeem.log; }
  # .../g/<host_id>/<grant_id>#<secret>: the host id keys the pinned entry.
  HOST_ID="$(printf '%s' "${URL%%#*}" | awk -F/ '{print $(NF-1)}')"
  OUT=$(docker exec -u ubuntu "$CONTAINER" sh -c \
    "ssh -i /tmp/v/id_ed25519 -o CertificateFile=/tmp/v/id_ed25519-cert.pub \
      -o IdentitiesOnly=yes -o UserKnownHostsFile=/tmp/v/known_hosts \
      -o StrictHostKeyChecking=yes -o HostKeyAlias=$HOST_ID -o HostKeyAlgorithms=ssh-ed25519 \
      -o BatchMode=yes -o LogLevel=ERROR -l ubuntu -- 127.0.0.1 whoami" 2>&1 | tr -d '[:space:]')
  [ "$OUT" = "ubuntu" ] && ok "SSH login using the downloaded, signature-verified build" \
    || bad "ssh failed: $OUT"
fi

step "summary"
if [ "$EMULATED" -eq 1 ]; then
  printf '  %d passed, %d failed, %d skipped (emulated %s)\n' "$PASS" "$FAIL" "$SKIP" "$PLATFORM"
  printf '  binaries, signature verification and the full redemption path were\n'
  printf '  exercised on %s; the systemd sandbox was not.\n\n' "$PLATFORM"
else
  printf '  %d passed, %d failed\n\n' "$PASS" "$FAIL"
fi
[ "$FAIL" -eq 0 ]
