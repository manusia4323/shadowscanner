#!/usr/bin/env bash
# scripts/build-windows.sh — Skrip build cross-compilation ShadowScanner untuk Windows.
# Menghasilkan binary .exe (CGO_ENABLED=0) yang siap distribusi.
set -euo pipefail

# Tentukan direktori root proyek (satu tingkat di atas scripts/).
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUTPUT_DIR="${ROOT_DIR}/dist"
mkdir -p "$OUTPUT_DIR"

VERSION="${SHADOWSCANNER_VERSION:-1.0.0}"
LDFLAGS="-s -w" # Strip simbol debug untuk ukuran binary lebih kecil.

echo "==> Memulai build ShadowScanner untuk Windows (amd64 & arm64)..."

# Windows amd64
echo "  → Mengompilasi shadowscanner-windows-amd64.exe..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$LDFLAGS" \
    -o "${OUTPUT_DIR}/shadowscanner-windows-amd64.exe" ./main.go

# Windows arm64 (Surface Pro X, ARM devices)
echo "  → Mengompilasi shadowscanner-windows-arm64.exe..."
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="$LDFLAGS" \
    -o "${OUTPUT_DIR}/shadowscanner-windows-arm64.exe" ./main.go

echo "✓ Build Windows selesai."
echo "  Output: ${OUTPUT_DIR}/shadowscanner-windows-amd64.exe"
echo "  Output: ${OUTPUT_DIR}/shadowscanner-windows-arm64.exe"
ls -lh "${OUTPUT_DIR}"/shadowscanner-windows-*
