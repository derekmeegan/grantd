#!/usr/bin/env bash
#
# Build, sign and publish a grantd release.
#
# The signing step is separate from the build step and is manual. If a
# compromised build or distribution system can produce a signed release, the
# signature proves nothing. The artifact is a daemon that runs on customer
# machines, so the private key must live where the build system cannot reach
# it: a hardware token, or an offline machine.
set -euo pipefail

# ------------------------------------------------------------------ settings

VERSION=""
BUCKET="grantd-releases"
SIGNING_KEY="${GRANTD_SIGNING_KEY:-}"
PUBLISH=0
OUT=""

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m==> %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<USAGE
grantd release builder

  install/release.sh --version vX.Y.Z [--signing-key PATH] [--publish]

  --version V          release version, e.g. v0.1.0
  --signing-key PATH   ed25519 private key used to sign SHA256SUMS
                       (default: \$GRANTD_SIGNING_KEY)
  --out DIR            where to stage artifacts (default: a temp dir)
  --bucket NAME        R2 bucket to publish to (default: $BUCKET)
  --publish            upload to the R2 bucket via wrangler
USAGE
}

# ----------------------------------------------------------------- arguments

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --signing-key) SIGNING_KEY="$2"; shift 2 ;;
    --bucket) BUCKET="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --publish) PUBLISH=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown argument: $1" ;;
  esac
done

[ -n "$VERSION" ] || { usage; die "--version is required"; }
case "$VERSION" in v[0-9]*) ;; *) die "version must look like v0.1.0" ;; esac
[ -n "$SIGNING_KEY" ] || die "a signing key is required; releases are never published unsigned"
[ -f "$SIGNING_KEY" ] || die "no such signing key: $SIGNING_KEY"

if [ -n "$(git -C "$REPO" status --porcelain 2>/dev/null)" ]; then
  warn "the working tree has uncommitted changes; the manifest will name a commit that does not match the build"
fi

[ -n "$OUT" ] || OUT="$(mktemp -d)"
STAGE="$OUT/$VERSION"
mkdir -p "$STAGE"

# --------------------------------------------------------------------- build

log "building $VERSION"
COMMIT="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
for arch in amd64 arm64; do
  for cmd in grantd grant-signer; do
    # -trimpath removes local paths and CGO is off, so nothing of the build
    # host ends up in a signed artifact.
    ( cd "$REPO/go" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
        go build -trimpath -ldflags "-s -w -buildid=" \
          -o "$STAGE/${cmd}-linux-${arch}" "./cmd/$cmd" )
  done
done
log "built 4 artifacts"

# The installer checks this file against the version it asked for. It is
# hashed with the binaries, so an old signed release cannot be served under a
# new version path.
printf '%s\n' "$VERSION" > "$STAGE/VERSION"

# -------------------------------------------------------------------- hashes

( cd "$STAGE" && sha256sum \
    grantd-linux-amd64 grantd-linux-arm64 \
    grant-signer-linux-amd64 grant-signer-linux-arm64 \
    VERSION > SHA256SUMS )
log "hashed"

# ----------------------------------------------------------------- signature

log "signing SHA256SUMS"
# ssh-keygen -Y sign refuses to overwrite a signature without a prompt.
rm -f "$STAGE/SHA256SUMS.sig"
ssh-keygen -Y sign -f "$SIGNING_KEY" -n grantd-release "$STAGE/SHA256SUMS" >/dev/null \
  || die "signing failed"
SIGNER_PUB="$(ssh-keygen -y -f "$SIGNING_KEY")"

# Verify with the same command the installer uses. A release the installer
# rejects must never leave this machine.
printf 'grantd-release %s\n' "$SIGNER_PUB" > "$STAGE/allowed_signers"
ssh-keygen -Y verify -f "$STAGE/allowed_signers" -I grantd-release -n grantd-release \
    -s "$STAGE/SHA256SUMS.sig" < "$STAGE/SHA256SUMS" >/dev/null \
  || die "the signature this script just produced does not verify"
rm -f "$STAGE/allowed_signers"
log "signature verified with the installer's own verification path"

# ------------------------------------------------------------------ manifest

cat > "$STAGE/manifest.json" <<JSON
{
  "version": "$VERSION",
  "commit": "$COMMIT",
  "protocol_version": 1,
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "platforms": ["linux/amd64", "linux/arm64"],
  "artifacts": [
$(cd "$STAGE" && sed 's/^\([0-9a-f]*\)  \(.*\)$/    {"name": "\2", "sha256": "\1"},/' SHA256SUMS | sed '$ s/,$//')
  ],
  "signing_key": "$SIGNER_PUB"
}
JSON
printf '{"version": "%s", "commit": "%s"}\n' "$VERSION" "$COMMIT" > "$OUT/latest.json"
log "manifest written"

echo
echo "staged at $STAGE"
( cd "$STAGE" && ls -1 )

# ------------------------------------------------------------------- publish

if [ "$PUBLISH" -eq 1 ]; then
  command -v npx >/dev/null 2>&1 || die "npx is required to publish"
  log "publishing to r2://$BUCKET"

  # Uploads retry, and latest.json is written only after every artifact is
  # confirmed present. The order already mattered — latest.json last means a
  # failed publish leaves the previous release intact rather than pointing at a
  # half-uploaded one — but a single dropped connection would still strand a
  # partial directory in the bucket. Both halves are now checked.
  put() { # put LOCAL_FILE REMOTE_KEY [EXTRA_ARGS...]
    local file="$1" key="$2"; shift 2
    local attempt=1
    while [ "$attempt" -le 3 ]; do
      if ( cd "$REPO/cloudflare" && npx wrangler r2 object put "$BUCKET/$key" \
             --file="$file" --remote "$@" >/dev/null 2>&1 ); then
        return 0
      fi
      echo "    retrying $key (attempt $attempt failed)" >&2
      attempt=$((attempt + 1))
      sleep 3
    done
    die "could not upload $key after 3 attempts"
  }

  for f in "$STAGE"/*; do
    name="$(basename "$f")"
    put "$f" "$VERSION/$name"
    echo "    $VERSION/$name"
  done

  # Verify what is actually readable before advertising it. wrangler reporting
  # success is not the same as the object being fetchable.
  log "verifying the published release"
  for f in "$STAGE"/*; do
    name="$(basename "$f")"
    ( cd "$REPO/cloudflare" && npx wrangler r2 object get "$BUCKET/$VERSION/$name" \
        --remote --file=/dev/null >/dev/null 2>&1 ) \
      || die "$VERSION/$name is not readable back from the bucket"
  done
  echo "    all $(ls -1 "$STAGE" | wc -l | tr -d ' ') objects readable"

  put "$OUT/latest.json" "latest.json" --content-type=application/json
  echo "    latest.json"
  log "published"
fi
