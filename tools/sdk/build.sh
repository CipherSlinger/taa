#!/bin/bash
# Build script for teecrypto GUI and CLI tools

set -euo pipefail

echo "=========================================="
echo "  Building teecrypto tools"
echo "=========================================="
echo ""

# Build GUI version (Go, legacy)
echo "=== [1/3] Building GUI version (Go, legacy) ==="

cd gui

# Find rsrc tool
RSRC_CMD=""
if command -v rsrc &> /dev/null; then
    RSRC_CMD="rsrc"
elif [ -x "$HOME/go/bin/rsrc" ]; then
    RSRC_CMD="$HOME/go/bin/rsrc"
elif [ -x "/usr/local/bin/rsrc" ]; then
    RSRC_CMD="/usr/local/bin/rsrc"
fi

# Try to use rsrc if available
if [ -n "$RSRC_CMD" ]; then
    echo "Embedding manifest with rsrc ($RSRC_CMD)..."
    $RSRC_CMD -manifest teecrypto-gui.exe.manifest -o resource_windows.syso
    EMBEDDED=true
elif [ -f "resource_windows.syso" ]; then
    echo "Using existing resource file..."
    EMBEDDED=true
else
    echo "Warning: rsrc not found and no resource file exists."
    echo "Building without embedded manifest (will need external .manifest file)"
    EMBEDDED=false
fi

# Build GUI executable to cmd directory
echo "Building GUI executable..."
if [ "$EMBEDDED" = true ]; then
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-H windowsgui" -o ../cmd/teecrypto-gui.exe .
    rm -f resource_windows.syso
    echo "✓ GUI build complete: cmd/teecrypto-gui.exe (manifest embedded)"
else
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ../cmd/teecrypto-gui.exe .
    echo "✓ GUI build complete: cmd/teecrypto-gui.exe"
    echo "  Note: Copy gui/teecrypto-gui.exe.manifest to cmd/ directory for modern styles"
fi

cd ..

echo ""

# Build Tauri GUI version
echo "=== [2/3] Building Tauri GUI version ==="

cd gui-tauri/src-tauri

echo "Building Tauri GUI executable..."
cargo xwin build --target x86_64-pc-windows-msvc --release

EXE_SRC="target/x86_64-pc-windows-msvc/release/teecrypto-gui.exe"
EXE_DST="../../cmd/teecrypto-gui.exe"

if [ -f "$EXE_SRC" ]; then
    cp "$EXE_SRC" "$EXE_DST"
    echo "✓ Tauri GUI build complete: cmd/teecrypto-gui.exe"
else
    echo "✗ Build output not found: $EXE_SRC"
    exit 1
fi

cd ../..

echo ""

# Build CLI version
echo "=== [3/3] Building CLI version ==="

cd cli

echo "Building CLI executable..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ../cmd/teecrypto-cli.exe .
echo "✓ CLI build complete: cmd/teecrypto-cli.exe"

cd ..

echo ""
echo "=========================================="
echo "  All builds complete!"
echo "=========================================="
echo ""
echo "Output files:"
echo "  - cmd/teecrypto-gui.exe  (Tauri GUI version, recommended)"
echo "  - cmd/teecrypto-cli.exe  (CLI version, auto-detect)"
echo ""
echo "Note: Go GUI version output is also in cmd/teecrypto-gui.exe but will be overwritten by Tauri GUI"
echo ""
echo "Usage:"
echo "  Tauri GUI: Double-click teecrypto-gui.exe (recommended)"
echo "  CLI: Double-click teecrypto-cli.exe (auto-detect .pem and files)"
echo "  BAT: Double-click encrypt.bat (interactive selection)"
echo ""
