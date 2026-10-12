#!/usr/bin/env bash
# scripts/build-linux.sh — Skrip build cross-compilation ShadowScanner untuk Linux.
# Menghasilkan binary statis (CGO_ENABLED=0) yang siap distribusi.
set -euo pipefail

# Tentukan direktori root proyek (satu tingkat di atas scripts/).
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUTPUT_DIR="${ROOT_DIR}/dist"
mkdir -p "$OUTPUT_DIR"

VERSION="${SHADOWSCANNER_VERSION:-1.0.0}"
LDFLAGS="-s -w" # Strip simbol debug untuk ukuran binary lebih kecil.

echo "==> Memulai build ShadowScanner untuk Linux (amd64 & arm64)..."

# Linux amd64
echo "  → Mengompilasi shadowscanner-linux-amd64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$LDFLAGS" \
    -o "${OUTPUT_DIR}/shadowscanner-linux-amd64" ./main.go

# Linux arm64 (Raspberry Pi, ARM server)
echo "  → Mengompilasi shadowscanner-linux-arm64..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$LDFLAGS" \
    -o "${OUTPUT_DIR}/shadowscanner-linux-arm64" ./main.go

echo "✓ Build Linux selesai."
echo "  Output: ${OUTPUT_DIR}/shadowscanner-linux-amd64"
echo "  Output: ${OUTPUT_DIR}/shadowscanner-linux-arm64"
ls -lh "${OUTPUT_DIR}"/shadowscanner-linux-*
