#!/bin/bash
# ── Build ExoChain Rust → WASM ─────────────────────────────────
# Compiles 28K+ lines of Rust governance engine to WASM for Node.js
#
# Prerequisites:
#   cargo install wasm-pack
#   (wasm-pack pinned to 0.2.100 for Rust 1.86 compat)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
WASM_OUT="$REPO_ROOT/packages/exochain-wasm/wasm"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ExoChain WASM Build                                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Source:  $REPO_ROOT/crates/exochain-wasm"
echo "║  Output:  $WASM_OUT"
echo "╚══════════════════════════════════════════════════════════════╝"

# Check prerequisites
if ! command -v wasm-pack &>/dev/null; then
  echo "❌ wasm-pack not found. Install with: cargo install wasm-pack@0.13.1 --locked"
  exit 1
fi

if [ ! -d "$REPO_ROOT/crates/exochain-wasm" ]; then
  echo "❌ ExoChain repo not found at $REPO_ROOT"
  echo "   Set EXOCHAIN_ROOT env var to point to the exochain repo"
  exit 1
fi

# Build
echo ""
echo "🔨 Building WASM (release mode)..."
cd "$REPO_ROOT"

wasm-pack build crates/exochain-wasm \
  --target nodejs \
  --release \
  --out-dir "$WASM_OUT"

# Clean up wasm-pack artifacts we don't need
rm -f "$WASM_OUT/.gitignore" "$WASM_OUT/package.json" "$WASM_OUT/README.md"

echo ""
echo "✅ WASM build complete!"
echo "   Binary: $(du -h "$WASM_OUT/exochain_wasm_bg.wasm" | cut -f1) $(basename "$WASM_OUT/exochain_wasm_bg.wasm")"
echo ""

# Verify
echo "🧪 Running WASM test suite..."
cd "$REPO_ROOT"
node packages/exochain-wasm/test.mjs
