#!/usr/bin/env bash
#
# Build, sign and publish a grantd release.
#
# The signing step is deliberately separate from the build step and deliberately
# manual. If a compromise of the build or distribution infrastructure were
# sufficient to produce a signed release, the signature would be decoration —
# and since the artifact being signed is a daemon that runs on customer
# machines, that would turn a CI compromise into a fleet compromise.
#
# The private key must live somewhere the build system cannot reach: a hardware
# token, or an offline machine.
set -euo pipefail

VERSION=""
BUCKET="grantd-releases"
SIGNING_KEY="${GRANTD_SIGNING_KEY:-}"
PUBLISH=0
OUT=""

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<USAGE
grantd release builder

  install/release.sh --version vX.Y.Z [--signing-key PATH] [--publish]

  --version PATH       release version, e.g. v0.1.0
  --signing-key PATH   ed25519 private key used to sign SHA256SUMS
                       (default: \$GRANTD_SIGNING_KEY)
  --out DIR            where to stage artifacts (default: a temp dir)
  --publish            upload to the R2 bucket "$BUCKET" via wrangler
USAGE
}

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

[ -n "$OUT" ] || OUT="$(mktemp -d)"
STAGE="$OUT/$VERSION"
mkdir -p "$STAGE"

# ------------------------------------------------------------------- build

log "building $VERSION"
COMMIT="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
for arch in amd64 arm64; do
  for cmd in grantd grant-signer; do
    # Reproducibility matters for a signed artifact: -trimpath removes local
    # paths, and CGO is off so there is nothing of the build host in the binary.
    ( cd "$REPO/go" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
        go build -trimpath -ldflags "-s -w -buildid=" \
          -o "$STAGE/${cmd}-linux-${arch}" "./cmd/$cmd" )
  done
done
log "built 4 artifacts"

# ------------------------------------------------------------------- hashes

( cd "$STAGE" && sha256sum ./*-linux-* | sed 's|\./||' > SHA256SUMS )
log "hashed"

# ------------------------------------------------------------------- signature

log "signing SHA256SUMS"
ssh-keygen -Y sign -f "$SIGNING_KEY" -n grantd-release "$STAGE/SHA256SUMS" >/dev/null 2>&1 \
  || die "signing failed"
SIGNER_PUB="$(ssh-keygen -y -f "$SIGNING_KEY")"

# Verify the signature we just made, with the same command the installer uses.
# A release that the installer would reject must never leave this machine.
printf 'grantd-release %s\n' "$SIGNER_PUB" > "$STAGE/allowed_signers"
ssh-keygen -Y verify -f "$STAGE/allowed_signers" -I grantd-release -n grantd-release \
    -s "$STAGE/SHA256SUMS.sig" < "$STAGE/SHA256SUMS" >/dev/null \
  || die "the signature this script just produced does not verify"
rm -f "$STAGE/allowed_signers"
log "signature verified with the installer's own verification path"

# ------------------------------------------------------------------- manifest

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
  ( cd "$REPO/cloudflare"
    for f in "$STAGE"/*; do
      name="$(basename "$f")"
      npx wrangler r2 object put "$BUCKET/$VERSION/$name" --file="$f" --remote >/dev/null
      echo "    $VERSION/$name"
    done
    npx wrangler r2 object put "$BUCKET/latest.json" --file="$OUT/latest.json" \
      --content-type=application/json --remote >/dev/null
    echo "    latest.json" )
  log "published"
fi
