#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# 创建 mock docker 命令
MOCK_BIN="$TMP_DIR/bin"
mkdir -p "$MOCK_BIN"
cat > "$MOCK_BIN/docker" <<'MOCK_DOCKER'
#!/usr/bin/env bash
cmd="${1:-}"
case "$cmd" in
  ps)
    echo "taa-env-slim-v2"
    exit 0
    ;;
  inspect)
    if [[ "$*" == *Config.Image* ]]; then
      echo "taa-env:slim-v2"
    elif [[ "$*" == *Image* ]]; then
      echo "img-123"
    fi
    exit 0
    ;;
  exec)
    # 若执行的是 test，模拟 lib 不存在，促使触发 transferring full ollama bundle
    if [[ "$*" == *"test -f"* ]]; then
      exit 1
    fi
    # 模拟接收 tar 流
    if [[ "$*" == *"tar -xf"* ]]; then
      cat >/dev/null
      exit 0
    fi
    exit 0
    ;;
  run|start|rm|chmod)
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
MOCK_DOCKER
chmod +x "$MOCK_BIN/docker"

set +e
output=$(PATH="$MOCK_BIN:$PATH" \
  FORCE_QWEN_COPY=true \
  OLLAMA_READY_TIMEOUT=1 \
  OLLAMA_READY_INTERVAL=1 \
  "$ROOT_DIR/deploy.sh" docker qwen 2>&1)
status=$?
set -e

# 核心断言：绝不能出现 resolve_ollama_model_artifacts: command not found
if grep -q "resolve_ollama_model_artifacts: command not found" <<<"$output"; then
  echo "FAIL: detected resolve_ollama_model_artifacts command not found in sub-shell!" >&2
  echo "$output" >&2
  exit 1
fi
echo "PASS: no sub-shell command not found error"
