#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DOCKER_DIR/../.." && pwd)"
LOCAL_ENV_FILE="${NODE_LOCAL_ENV_FILE:-$DOCKER_DIR/env/node.local.env}"

load_local_env_defaults() {
  [[ -f "$LOCAL_ENV_FILE" ]] || return 0

  local names=(
    NODE_ID_OVERRIDE NODE_IP_OVERRIDE NODE_INSTANCE NODE_API_URL
    API_PORT API_HOST_PORT COMPOSE_PROJECT_NAME
    LATTI_DATA_ROOT NODE_RUNTIME_DIR HOST_DATA_DIR HOST_REDIS_DIR
    HOST_RUNTIME_DIR HOST_CUDA_DIR CONTAINER_CUDA_DIR
    LATTI_SERVER_BASE_IMAGE
    LOCAL_REDIS_DB LOCAL_REDIS_KEY_PREFIX LOCAL_REDIS_PASSWORD
    LOCAL_REDIS_BIND_HOST LOCAL_REDIS_HOST_PORT
    GPU_DEVICES
    GPU_UNAVAILABLE_EXIT_ENABLED GPU_UNAVAILABLE_EXIT_THRESHOLD GPU_UNAVAILABLE_EXIT_CODE
  )
  local name
  declare -A was_set=()
  declare -A old_value=()

  for name in "${names[@]}"; do
    if [[ -v $name ]]; then
      was_set["$name"]=1
      old_value["$name"]="${!name}"
    fi
  done

  set -a
  # shellcheck disable=SC1090
  source "$LOCAL_ENV_FILE"
  set +a

  for name in "${names[@]}"; do
    if [[ -n "${was_set[$name]:-}" ]]; then
      printf -v "$name" '%s' "${old_value[$name]}"
      export "$name"
    fi
  done
}

load_local_env_defaults

ensure_local_base_image_alias() {
  [[ -n "${LATTI_SERVER_BASE_IMAGE:-}" ]] && return 0

  local alias_image="latti-local/ubuntu:24.04"
  local server_image="${LATTI_SERVER_IMAGE:-latti/latti-server:latest}"
  if docker image inspect "$alias_image" >/dev/null 2>&1; then
    export LATTI_SERVER_BASE_IMAGE="$alias_image"
    return 0
  fi

  if docker image inspect "ubuntu:24.04" >/dev/null 2>&1; then
    docker tag ubuntu:24.04 "$alias_image"
    export LATTI_SERVER_BASE_IMAGE="$alias_image"
    return 0
  fi

  if docker image inspect "$server_image" >/dev/null 2>&1; then
    docker tag "$server_image" "$alias_image"
    export LATTI_SERVER_BASE_IMAGE="$alias_image"
    return 0
  fi

  export LATTI_SERVER_BASE_IMAGE="ubuntu:24.04"
}

ensure_local_base_image_alias

NODE_ID="${NODE_ID_OVERRIDE:-${NODE_ID:-$(hostname -s)}}"
NODE_ID_LOWER="$(printf '%s' "$NODE_ID" | tr '[:upper:]' '[:lower:]')"
NODE_IP="${NODE_IP_OVERRIDE:-${NODE_IP:-$(hostname -I 2>/dev/null || true)}}"
NODE_IP="${NODE_IP%% *}"
NODE_IP="${NODE_IP:-127.0.0.1}"
API_PORT="${API_PORT:-58996}"

if [[ "$API_PORT" == "9300" && "${ALLOW_LEGACY_9300:-}" != "1" ]]; then
  echo "Refusing to start node stack on API_PORT=9300. Set ALLOW_LEGACY_9300=1 only if you intentionally want to use 9300." >&2
  exit 2
fi

NODE_INSTANCE="${NODE_INSTANCE:-${NODE_ID_LOWER}-${API_PORT}}"
NODE_INSTANCE="$(printf '%s' "$NODE_INSTANCE" | tr '[:upper:]' '[:lower:]')"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-fhe-node-${NODE_INSTANCE}}"
API_HOST_PORT="${API_HOST_PORT:-$API_PORT}"

export NODE_ID
export NODE_ID_LOWER
export NODE_IP
export API_PORT
export API_HOST_PORT
export NODE_INSTANCE
export COMPOSE_PROJECT_NAME
LATTI_DATA_ROOT="${LATTI_DATA_ROOT:-${REPO_ROOT}/var/latti}"
NODE_RUNTIME_DIR="${NODE_RUNTIME_DIR:-${LATTI_DATA_ROOT}/${NODE_INSTANCE}}"

export NODE_API_URL="${NODE_API_URL:-http://${NODE_IP}:${API_PORT}}"
export LOCAL_REDIS_DB="${LOCAL_REDIS_DB:-14}"
export LOCAL_REDIS_BIND_HOST="${LOCAL_REDIS_BIND_HOST:-127.0.0.1}"
export LOCAL_REDIS_HOST_PORT="${LOCAL_REDIS_HOST_PORT:-58998}"
export LOCAL_REDIS_KEY_PREFIX="${LOCAL_REDIS_KEY_PREFIX:-Latti-${NODE_ID}:}"
export LATTI_DATA_ROOT
export NODE_RUNTIME_DIR
export HOST_DATA_DIR="${HOST_DATA_DIR:-${NODE_RUNTIME_DIR}/data}"
export HOST_REDIS_DIR="${HOST_REDIS_DIR:-${NODE_RUNTIME_DIR}/redis}"
export HOST_RUNTIME_DIR="${HOST_RUNTIME_DIR:-${REPO_ROOT}/third_party/latti-ai-runtime}"

case "${1:-}" in
  up|create|run|start)
    mkdir -p "$HOST_DATA_DIR" "$HOST_REDIS_DIR"
    ;;
esac

cd "$DOCKER_DIR"
exec docker compose --project-name "$COMPOSE_PROJECT_NAME" --env-file env/node.env -f docker-compose.node.yml "$@"
