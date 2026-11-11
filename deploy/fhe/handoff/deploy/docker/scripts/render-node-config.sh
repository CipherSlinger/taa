#!/usr/bin/env bash
set -euo pipefail

NODE_ID="${NODE_ID_OVERRIDE:-${NODE_ID:-$(hostname -s)}}"
NODE_ID_LOWER="$(printf '%s' "$NODE_ID" | tr '[:upper:]' '[:lower:]')"
NODE_IP="${NODE_IP_OVERRIDE:-${NODE_IP:-$(hostname -I 2>/dev/null || true)}}"
NODE_IP="${NODE_IP%% *}"
NODE_IP="${NODE_IP:-127.0.0.1}"
API_PORT="${API_PORT:-58996}"
NODE_INSTANCE="${NODE_INSTANCE:-${NODE_ID_LOWER}-${API_PORT}}"
NODE_INSTANCE="$(printf '%s' "$NODE_INSTANCE" | tr '[:upper:]' '[:lower:]')"

export NODE_ID
export NODE_ID_LOWER
export NODE_IP
export API_PORT
export NODE_INSTANCE
export NODE_API_URL="${NODE_API_URL:-http://${NODE_IP}:${API_PORT}}"
export LOCAL_REDIS_DB="${LOCAL_REDIS_DB:-14}"
export LOCAL_REDIS_KEY_PREFIX="${LOCAL_REDIS_KEY_PREFIX:-Latti-${NODE_ID}:}"
export GPU_UNAVAILABLE_EXIT_ENABLED="${GPU_UNAVAILABLE_EXIT_ENABLED:-true}"
export GPU_UNAVAILABLE_EXIT_THRESHOLD="${GPU_UNAVAILABLE_EXIT_THRESHOLD:-5}"
export GPU_UNAVAILABLE_EXIT_CODE="${GPU_UNAVAILABLE_EXIT_CODE:-75}"
export ISOLATE_GPU_TASK_PROCESS="${ISOLATE_GPU_TASK_PROCESS:-false}"
export RESIDENT_SERVER_ENABLED="${RESIDENT_SERVER_ENABLED:-true}"
export RESIDENT_MAX_SERVERS="${RESIDENT_MAX_SERVERS:-4}"
export CONFIG_PATH="${CONFIG_PATH:-/config/config.toml}"

TEMPLATE_PATH="${NODE_CONFIG_TEMPLATE:-/deploy/configs/node.toml.template}"
mkdir -p "$(dirname "$CONFIG_PATH")"

python3 - "$TEMPLATE_PATH" "$CONFIG_PATH" <<'PY'
import os
import string
import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src, 'r', encoding='utf-8') as f:
    template = string.Template(f.read())
with open(dst, 'w', encoding='utf-8') as f:
    f.write(template.safe_substitute(os.environ))
PY

printf 'Rendered %s for node_instance=%s node_id=%s api_url=%s redis_db=%s key_prefix=%s\n' \
  "$CONFIG_PATH" "$NODE_INSTANCE" "$NODE_ID" "$NODE_API_URL" "$LOCAL_REDIS_DB" "$LOCAL_REDIS_KEY_PREFIX"
