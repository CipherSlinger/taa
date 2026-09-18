#!/bin/bash
# Build Tauri GUI and copy to cmd directory

set -e

echo "Building Tauri GUI for Windows..."
cargo xwin build --target x86_64-pc-windows-msvc --release

EXE_SRC="src-tauri/target/x86_64-pc-windows-msvc/release/teecrypto-gui.exe"
EXE_DST="../cmd/teecrypto-gui.exe"

if [ -f "$EXE_SRC" ]; then
    cp "$EXE_SRC" "$EXE_DST"
    echo "✓ Copied to $EXE_DST"
    ls -lh "$EXE_DST"
else
    echo "✗ Build output not found: $EXE_SRC"
    exit 1
fi
