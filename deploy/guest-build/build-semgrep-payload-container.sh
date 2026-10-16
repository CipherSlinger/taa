#!/usr/bin/env bash
#
# build-semgrep-payload-container.sh -- build the semgrep payload that deploy.sh injects into a
# TAA container or kata pod (REMOTE_SEMGREP_BUNDLE).
#
# Why this is a script and not a committed archive: the payload is a Python site-packages tree
# plus semgrep-core, ~350 MiB unpacked, none of which belongs in git. This file is the recipe;
# out/semgrep-bundle.tar.gz is derived state and gitignored.
#
# Why this differs from build-semgrep-payload.sh (the initrd variant): the initrd has no Python, so
# that recipe ships an entire jammy interpreter and targets glibc 2.35. A TAA container image is
# Ubuntu 24.04 with python3.12 already on PATH, so this recipe installs nothing but site-packages
# and relies on the image's own interpreter. The two payloads are therefore not interchangeable:
# this one is shaped by whichever image you point it at.
#
# The rules are deliberately not part of the bundle. They change with the checkout (so does the
# Go-side rule table that reads them), so deploy.sh streams $SEMGREP_RULES_SOURCE into the
# container on every deploy and this archive stays a pure third-party runtime.
#
# Output layout: paths relative to the filesystem root, so the container extracts it with
# `tar -xzf - -C /`:
#
#   opt/taa/semgrep/pylib/**           site-packages (semgrep, semgrep-core, ...)
#   opt/taa/semgrep/MANIFEST           version, source image, pip freeze
#   usr/local/bin/semgrep              wrapper that pins PYTHONPATH and PATH
#   usr/local/bin/pysemgrep            the CLI the wrapper's launcher resolves through PATH
#
# Usage: ./build-semgrep-payload-container.sh
#
# Environment (all optional):
#   CONTAINER_IMAGE      taa-env:slim-v2   image whose Python the payload is built for
#   IMAGE_ARCHIVE        $ROOT_DIR/deploy/taa-env-slim-v2.tar.gz  loaded when the image is absent
#   SEMGREP_VERSION      1.177.0           (keep in step with deploy.sh)
#   OUT                  $SCRIPT_DIR/out/semgrep-bundle.tar.gz
#   PIP_INDEX_URL        passed through to pip when set
#   KEEP_BUILDER         false             leave the build container behind for inspection

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [[ ! -f "$ROOT_DIR/go.mod" ]]; then
  echo "error: $ROOT_DIR is not the repository root (no go.mod); refusing to guess paths" >&2
  exit 1
fi

CONTAINER_IMAGE="${CONTAINER_IMAGE:-taa-env:slim-v2}"
IMAGE_ARCHIVE="${IMAGE_ARCHIVE:-$ROOT_DIR/deploy/taa-env-slim-v2.tar.gz}"
SEMGREP_VERSION="${SEMGREP_VERSION:-1.177.0}"
OUT="${OUT:-$SCRIPT_DIR/out/semgrep-bundle.tar.gz}"
KEEP_BUILDER="${KEEP_BUILDER:-false}"

CONTAINER_SEMGREP_DIR=/opt/taa/semgrep
CONTAINER_PYLIB_DIR="$CONTAINER_SEMGREP_DIR/pylib"

BUILDER="taa-semgrep-build-$$"
VERIFIER="taa-semgrep-verify-$$"

cleanup() {
  local rc=$?
  if [[ "$KEEP_BUILDER" != true ]]; then
    docker rm -f "$BUILDER" >/dev/null 2>&1 || true
  else
    echo "builder容器保留: $BUILDER" >&2
  fi
  docker rm -f "$VERIFIER" >/dev/null 2>&1 || true
  return $rc
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$1"; }

step "前置检查"
command -v docker >/dev/null 2>&1 || { echo "error: docker is required" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "error: docker daemon is not reachable" >&2; exit 1; }

if ! docker image inspect "$CONTAINER_IMAGE" >/dev/null 2>&1; then
  if [[ -f "$IMAGE_ARCHIVE" ]]; then
    echo "loading $CONTAINER_IMAGE from $IMAGE_ARCHIVE"
    docker load -i "$IMAGE_ARCHIVE" >/dev/null
  else
    echo "error: image $CONTAINER_IMAGE not found and no archive at $IMAGE_ARCHIVE" >&2
    exit 1
  fi
fi
IMAGE_ID="$(docker image inspect -f '{{.Id}}' "$CONTAINER_IMAGE")"
echo "image  : $CONTAINER_IMAGE ($IMAGE_ID)"

step "创建构建容器"
docker run -d --name "$BUILDER" --entrypoint sleep "$CONTAINER_IMAGE" infinity >/dev/null

PY_VERSION="$(docker exec "$BUILDER" /usr/bin/python3 -V 2>&1)"
echo "python : $PY_VERSION (from the image; the payload carries no interpreter)"

step "安装 semgrep $SEMGREP_VERSION 到 $CONTAINER_PYLIB_DIR"
docker exec -i \
  -e SEMGREP_VERSION="$SEMGREP_VERSION" \
  -e PYLIB_DIR="$CONTAINER_PYLIB_DIR" \
  -e PIP_INDEX_URL="${PIP_INDEX_URL:-}" \
  "$BUILDER" sh -s <<'SH'
set -eu
mkdir -p "$PYLIB_DIR"
set -- --target "$PYLIB_DIR" --no-cache-dir --disable-pip-version-check "semgrep==$SEMGREP_VERSION"
if [ -n "$PIP_INDEX_URL" ]; then
  set -- "$@" --index-url "$PIP_INDEX_URL"
fi
# --target keeps the install out of the image's own site-packages; --break-system-packages is what
# pip's PEP 668 guard requires on Ubuntu 24.04 (pip >= 23.0.1) even for a --target install.
python3 -m pip install --break-system-packages "$@"
SH

step "写入 CLI 包装脚本"
# The wheel's bin/semgrep is a launcher that resolves pysemgrep through PATH, and a --target
# install leaves neither the site-packages directory on sys.path nor its bin on PATH. Both are
# pinned here, or `semgrep --version` fails with "execvp pysemgrep: No such file or directory".
docker exec -i -e PYLIB_DIR="$CONTAINER_PYLIB_DIR" "$BUILDER" sh -s <<'SH'
set -eu
mkdir -p /usr/local/bin
for name in semgrep pysemgrep; do
  cat > "/usr/local/bin/$name" <<EOF
#!/bin/sh
# Entry point for the semgrep CLI inside a TAA container. Both the site-packages directory and the
# interpreter are pinned because a --target install puts neither on the default sys.path or PATH;
# PATH carries pylib/bin because this wheel's semgrep is a thin launcher that execs pysemgrep by
# name, and the console script beside it is the only copy on the image.
#
# The two SEMGREP_* variables are what makes the CLI usable in the container it is installed into.
# semgrep dispatches to its OCaml semgrep-core binary, which dials semgrep.dev before doing any
# work; a TAA container has no route off the host, and that call blocks there instead of failing,
# so the CLI prints its version and then never exits. Setting them here rather than at each call
# site is what keeps every caller -- deploy.sh, taa's own audit path, someone typing semgrep by
# hand -- from having to know that.
PYTHONPATH=$PYLIB_DIR
PATH=$PYLIB_DIR/bin:\$PATH
SEMGREP_SEND_METRICS=off
SEMGREP_ENABLE_VERSION_CHECK=0
export PYTHONPATH PATH SEMGREP_SEND_METRICS SEMGREP_ENABLE_VERSION_CHECK
exec /usr/bin/python3 $PYLIB_DIR/bin/$name "\$@"
EOF
  chmod 0755 "/usr/local/bin/$name"
done
SH

step "写入 MANIFEST"
docker exec -i \
  -e SEMGREP_VERSION="$SEMGREP_VERSION" \
  -e CONTAINER_IMAGE="$CONTAINER_IMAGE" \
  -e IMAGE_ID="$IMAGE_ID" \
  -e PY_VERSION="$PY_VERSION" \
  -e PYLIB_DIR="$CONTAINER_PYLIB_DIR" \
  -e MANIFEST="$CONTAINER_SEMGREP_DIR/MANIFEST" \
  "$BUILDER" sh -s <<'SH'
set -eu
{
  echo "semgrep_version: $SEMGREP_VERSION"
  echo "source_image: $CONTAINER_IMAGE"
  echo "image_id: $IMAGE_ID"
  echo "python: $PY_VERSION"
  echo "built_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "packages:"
  python3 -m pip freeze --path "$PYLIB_DIR" 2>/dev/null | sed 's/^/  /' || true
} > "$MANIFEST"
SH

step "打包 $OUT"
mkdir -p "$(dirname "$OUT")"
docker exec "$BUILDER" tar -czf - \
  -C / opt/taa/semgrep usr/local/bin/semgrep usr/local/bin/pysemgrep > "$OUT"
echo "archive: $OUT ($(du -h "$OUT" | cut -f1), $(tar -tzf "$OUT" | wc -l) entries)"

step "在干净容器里验证"
# A fresh container from the same image with nothing but the archive extracted: that is what the
# pod looks like after deploy.sh runs, so it is the check that the payload is self-contained.
docker run -d --name "$VERIFIER" --entrypoint sleep "$CONTAINER_IMAGE" infinity >/dev/null
docker exec -i "$VERIFIER" sh -lc 'tar -xzf - -C /' < "$OUT"
VERIFIED_VERSION="$(docker exec "$VERIFIER" sh -lc 'semgrep --version 2>/dev/null | head -n 1')"
[[ -n "$VERIFIED_VERSION" ]] || { echo "error: semgrep is not runnable after extraction" >&2; exit 1; }
echo "verified: semgrep $VERIFIED_VERSION (extracted into $VERIFIER)"
docker rm -f "$VERIFIER" >/dev/null

step "输出结果摘要"
echo "payload : $OUT"
echo "semgrep : $VERIFIED_VERSION"
echo "注入方式: scp $OUT ${REMOTE_USER:-root}@<host>:<REMOTE_DIR>/semgrep-bundle.tar.gz"
echo "          或设置 SEMGREP_BUNDLE=$OUT 后由 deploy.sh remote 自行上传"
