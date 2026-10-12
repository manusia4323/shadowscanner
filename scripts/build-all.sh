#!/usr/bin/env bash
# scripts/build-all.sh — Skrip build lengkap ShadowScanner untuk semua platform
# target (Linux, Windows, macOS). Menghasilkan binary statis (CGO_ENABLED=0).
set -euo pipefail

# Tentukan direktori root proyek (satu tingkat di atas scripts/).
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUTPUT_DIR="${ROOT_DIR}/dist"
mkdir -p "$OUTPUT_DIR"

VERSION="${SHADOWSCANNER_VERSION:-1.0.0}"
LDFLAGS="-s -w"

# Hapus hasil build lama
rm -f "${OUTPUT_DIR}"/shadowscanner-*

echo "===================================================="
echo "  ShadowScanner v${VERSION} — Build Lintas Platform"
echo "===================================================="

# Fungsi helper untuk build
build_target() {
    local goos="$1"
    local goarch="$2"
    local ext="$3"
    local label="${goos}-${goarch}"
    local output="${OUTPUT_DIR}/shadowscanner-${label}${ext}"

    echo "  → Mengompilasi shadowscanner-${label}${ext}..."
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="$LDFLAGS" \
        -o "$output" ./main.go

    if [ ! -f "$output" ]; then
        echo "  ✗ GAGAL: shadowscanner-${label}${ext}"
        return 1
    fi
}

# 1. Linux
build_target linux amd64 "" && echo "    ✓ OK"
build_target linux arm64 "" && echo "    ✓ OK"

# 2. Windows
build_target windows amd64 ".exe" && echo "    ✓ OK"
build_target windows arm64 ".exe" && echo "    ✓ OK"

# 3. macOS
build_target darwin amd64 "" && echo "    ✓ OK"
build_target darwin arm64 "" && echo "    ✓ OK"

echo "===================================================="
echo "  ✓ Build Lengkap Selesai"
echo "===================================================="
echo ""
echo "Hasil binary ada di: ${OUTPUT_DIR}/"
ls -lh "${OUTPUT_DIR}"/shadowscanner-*
echo ""
echo "Ukuran total: $(du -sh "${OUTPUT_DIR}" | cut -f1)"
