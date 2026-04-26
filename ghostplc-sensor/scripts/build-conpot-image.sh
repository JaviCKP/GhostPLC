#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${CONPOT_BUILD_DIR:-/tmp/ghostplc-conpot-build}"
REPO_URL="https://github.com/mushorg/conpot.git"

if docker image inspect conpot:latest >/dev/null 2>&1; then
  echo "conpot:latest already exists"
  exit 0
fi

rm -rf "$BUILD_DIR"
git clone --depth 1 "$REPO_URL" "$BUILD_DIR"
docker build -t conpot:latest "$BUILD_DIR"

echo "Built conpot:latest"

