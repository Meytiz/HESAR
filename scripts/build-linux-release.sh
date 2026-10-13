#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test -f "$ROOT/backend/internal/api/dist/index.html" || { echo 'Stage the panel in GitHub Actions first.' >&2; exit 1; }
BUILD_VERSION="${BUILD_VERSION:?GitHub workflow must supply BUILD_VERSION}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%d)}"
mkdir -p "$ROOT/release"
python3 "$ROOT/scripts/fetch-release-cores.py"
cd "$ROOT/backend"
for ARCH in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath \
    -ldflags="-s -w -X main.Version=$BUILD_VERSION -X main.BuildDate=$BUILD_DATE" \
    -o "$ROOT/release/hesar-linux-$ARCH" ./cmd/hesar
  CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath \
    -ldflags="-s -w -X main.Version=$BUILD_VERSION" \
    -o "$ROOT/release/hesar-agent-linux-$ARCH" ./cmd/hesar-agent
done
python3 "$ROOT/scripts/package-linux-release.py" --version "$BUILD_VERSION" \
  --repository "${HESAR_REPOSITORY:-Meytiz/HESAR}"
