#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

pkg="$TMP_DIR/ollama-qwen"
mkdir -p "$pkg/lib/ollama" "$pkg/models/models"

cat > "$pkg/ollama" <<'BADBIN'
this is not a valid ollama executable
BADBIN
chmod +x "$pkg/ollama"

cat > "$pkg/start-ollama.sh" <<'SH'
#!/usr/bin/env sh
set -eu
DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec "$DIR/ollama" serve
SH
chmod +x "$pkg/start-ollama.sh"

set +e
output=$(OLLAMA_LOCAL_DIR="$pkg" \
  OLLAMA_PRUNE_SYNC=false \
  OLLAMA_READY_TIMEOUT=1 \
  OLLAMA_READY_INTERVAL=1 \
  "$ROOT_DIR/deploy.sh" docker qwen 2>&1)
status=$?
set -e

if [[ $status -eq 0 ]]; then
  echo "expected deploy.sh to reject invalid ollama binary, got success" >&2
  exit 1
fi

if ! grep -q "ollama binary is invalid or incomplete" <<<"$output"; then
  echo "expected explicit ollama binary integrity error" >&2
  echo "actual output:" >&2
  echo "$output" >&2
  exit 1
fi

if grep -q "did not become ready within" <<<"$output"; then
  echo "expected preflight failure before readiness timeout" >&2
  echo "actual output:" >&2
  echo "$output" >&2
  exit 1
fi
