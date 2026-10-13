#!/usr/bin/env bash
#
# build-semgrep-payload.sh -- build the Tier 1 semgrep payload that
# build-initrd.sh injects into the Kata CSV2 initrd.
#
# Why this is a script and not a committed directory: the payload is a Python
# runtime plus ~310 MiB of third-party wheels, none of which belongs in git.
# This file is the recipe; semgrep-payload/ is derived state and gitignored.
#
# Why jammy Python 3.10 and not the TAA container's Python 3.12: the guest
# rootfs is Ubuntu 22.04 (glibc 2.35). Ubuntu 24.04's python3.12 needs
# GLIBC_2.38 symbols, which that rootfs does not export (measured with
# objdump -T), so the interpreter has to come from jammy. The wheels follow
# the same constraint: semgrep 1.177.0 ships a manylinux_2_34 wheel, i.e. one
# that needs glibc >= 2.34 and therefore runs on the guest's 2.35. semgrep-core
# itself needs at most GLIBC_2.34, and it carries its own dependencies
# (libstdc++, libcurl, ...) in semgrep/bin/libs, so only libc comes from the
# guest.
#
# Output layout mirrors the guest rootfs, so build-initrd.sh can copy it in
# with a single `cp -a`:
#
#   semgrep-payload/rootfs/usr/bin/python3.10
#   semgrep-payload/rootfs/usr/lib/python3.10/**          (stdlib + lib-dynload)
#   semgrep-payload/rootfs/usr/lib/x86_64-linux-gnu/**    (libs the base lacks)
#   semgrep-payload/rootfs/usr/local/bin/semgrep          (wrapper on PATH)
#   semgrep-payload/rootfs/usr/local/bin/pysemgrep        (the CLI semgrep falls back to)
#   semgrep-payload/rootfs/opt/taa/semgrep/pylib/**       (site-packages)
#   semgrep-payload/rootfs/opt/taa/semgrep/rules/**       (same rules as the TAA image)
#   semgrep-payload/rootfs/opt/taa/semgrep/MANIFEST
#   semgrep-payload/rootfs/opt/taa/semgrep/pip-freeze.txt
#
# Usage: ./build-semgrep-payload.sh
#
# Environment (all optional):
#   SEMGREP_VERSION      1.177.0 (keep in step with deploy-docker.sh --scan-engine semgrep)
#   SEMGREP_RULES_SRC    $ROOT_DIR/models/audit/semgrep/rules
#   SEMGREP_PAYLOAD_DIR  $SCRIPT_DIR/semgrep-payload
#   BASE_INITRD          $SCRIPT_DIR/base/kata-containers-initrd-confidential-csv.img
#   PYTHON_IMAGE         ubuntu:22.04       (must be jammy: glibc 2.35)
#   PIP_IMAGE            taa-env:slim-v2    (any image with pip; never modified)
#   APT_MIRROR           http://mirrors.tuna.tsinghua.edu.cn/ubuntu
#   PIP_INDEX_URL        https://pypi.org/simple
#   PIP_CONSTRAINTS_SRC  /opt/taa/semgrep/pip-freeze.txt inside the TAA container
#   PIP_CONSTRAINTS_CONTAINER  taa-env-slim-v2 (the running arm the freeze came from)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [[ ! -f "$ROOT_DIR/go.mod" ]]; then
  echo "error: $ROOT_DIR is not the repository root (no go.mod); refusing to guess paths" >&2
  exit 1
fi

SEMGREP_VERSION="${SEMGREP_VERSION:-1.177.0}"
SEMGREP_RULES_SRC="${SEMGREP_RULES_SRC:-$ROOT_DIR/models/audit/semgrep/rules}"
SEMGREP_PAYLOAD_DIR="${SEMGREP_PAYLOAD_DIR:-$SCRIPT_DIR/semgrep-payload}"
BASE_INITRD="${BASE_INITRD:-$SCRIPT_DIR/base/kata-containers-initrd-confidential-csv.img}"
PYTHON_IMAGE="${PYTHON_IMAGE:-ubuntu:22.04}"
PIP_IMAGE="${PIP_IMAGE:-taa-env:slim-v2}"
APT_MIRROR="${APT_MIRROR:-http://mirrors.tuna.tsinghua.edu.cn/ubuntu}"
PIP_INDEX_URL="${PIP_INDEX_URL:-https://pypi.org/simple}"
PIP_CONSTRAINTS_SRC="${PIP_CONSTRAINTS_SRC:-/opt/taa/semgrep/pip-freeze.txt}"
PIP_CONSTRAINTS_CONTAINER="${PIP_CONSTRAINTS_CONTAINER:-taa-env-slim-v2}"

# semgrep 1.177.0's Linux wheel is tagged manylinux_2_34; the older tags are
# carried for its dependencies, which are built against older baselines. Adding
# a tag cannot pull in something the guest cannot run -- every tag here is
# glibc <= 2.34, and the guest has 2.35.
WHEEL_PLATFORMS=(
  manylinux_2_34_x86_64
  manylinux_2_28_x86_64
  manylinux2014_x86_64
  manylinux_2_17_x86_64
)

ROOTFS="$SEMGREP_PAYLOAD_DIR/rootfs"
WHEEL_DIR="$SEMGREP_PAYLOAD_DIR/wheels"
PYLIB="$ROOTFS/opt/taa/semgrep/pylib"

step() { echo "== $*"; }
info() { echo "   $*"; }
die()  { echo "error: $*" >&2; exit 1; }

# Everything below is staged by root inside a container, so the host user cannot
# always remove it again. Delegate the removal to the same runtime that created
# the files instead of making the build depend on host sudo.
#
# The delegated removal runs on PYTHON_IMAGE rather than PIP_IMAGE on purpose:
# PIP_IMAGE carries an ENTRYPOINT (start.sh), so a bare `docker run <image>
# rm ...` would run that script and ignore the command entirely.
rinse() {
  local target="$1"
  [[ -e "$target" ]] || return 0
  # A direct removal is tried first: it is instant and needs no container. Only
  # files staged by root inside the container defeat it, which is the case the
  # container is there for.
  if ! rm -rf "$target" 2>/dev/null || [[ -e "$target" ]]; then
    info "改用容器清理: $target"
    docker run --rm -v "$(dirname "$target"):/parent" "$PYTHON_IMAGE" \
      rm -rf "/parent/$(basename "$target")"
  fi
}

for cmd in docker gzip cpio sha256sum find; do
  command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
done
[[ -d "$SEMGREP_RULES_SRC" ]] || die "semgrep rules not found: $SEMGREP_RULES_SRC"
[[ -f "$BASE_INITRD" ]] || die "base initrd not found: $BASE_INITRD (run: build-initrd.sh fetch-base)"

# The base initrd's file list decides which shared libraries the payload has to
# carry. Reading it here rather than hardcoding a list keeps the payload honest
# as the base image moves: a library that stops being part of the base shows up
# as a copied file in the next build instead of as a runtime failure in the
# guest.
step "读取 base initrd 的文件清单"
base_libs="$(gzip -dc "$BASE_INITRD" | cpio -it 2>/dev/null | awk -F/ '{print $NF}' | LC_ALL=C sort -u)"
info "base entries: $(printf '%s\n' "$base_libs" | wc -l)"

rinse "$SEMGREP_PAYLOAD_DIR"
mkdir -p "$ROOTFS/usr/bin" "$ROOTFS/usr/lib" "$ROOTFS/usr/local/bin" "$ROOTFS/opt/taa/semgrep" "$WHEEL_DIR"

step "下载 semgrep $SEMGREP_VERSION 的 cp310 wheel（含完整依赖闭包）"
# --only-binary --python-version --platform is what makes a 3.12 host download a
# 3.10 closure: pip resolves against the tags given instead of the interpreter
# it runs on, so the payload does not depend on the build host's Python.
platform_args=()
for p in "${WHEEL_PLATFORMS[@]}"; do platform_args+=(--platform "$p"); done

# The TAA container's pip-freeze pins the exact versions its semgrep arm was built
# and measured with. Reusing it as constraints keeps the guest arm comparable to
# the arm the evidence was collected on, so a differing verdict can be attributed
# to the guest rather than to a different dependency set. The semgrep line itself
# is dropped: pip rejects a package that is both a requirement and an equal
# constraint.
#
# The freeze is written by deploy-docker.sh into the running container's writable
# layer, so a fresh `docker run` of that image cannot see it -- read it out of the
# running container first and only fall back to the image.
have_freeze=0
: > "$SEMGREP_PAYLOAD_DIR/pip-freeze.txt"
if docker cp "$PIP_CONSTRAINTS_CONTAINER:$PIP_CONSTRAINTS_SRC" "$SEMGREP_PAYLOAD_DIR/pip-freeze.raw" >/dev/null 2>&1; then
  grep -v '^semgrep==' "$SEMGREP_PAYLOAD_DIR/pip-freeze.raw" > "$SEMGREP_PAYLOAD_DIR/pip-freeze.txt" || true
  have_freeze=1
  info "constraints: $PIP_CONSTRAINTS_CONTAINER:$PIP_CONSTRAINTS_SRC ($(wc -l < "$SEMGREP_PAYLOAD_DIR/pip-freeze.txt") 行)"
elif docker run --rm --entrypoint sh "$PIP_IMAGE" -c "test -f '$PIP_CONSTRAINTS_SRC'" >/dev/null 2>&1; then
  docker run --rm --entrypoint sh "$PIP_IMAGE" -c "grep -v '^semgrep==' '$PIP_CONSTRAINTS_SRC'" \
    > "$SEMGREP_PAYLOAD_DIR/pip-freeze.txt"
  have_freeze=1
  info "constraints: $PIP_IMAGE:$PIP_CONSTRAINTS_SRC ($(wc -l < "$SEMGREP_PAYLOAD_DIR/pip-freeze.txt") 行)"
else
  info "constraints: 无（$PIP_CONSTRAINTS_CONTAINER 与 $PIP_IMAGE 里都没有 $PIP_CONSTRAINTS_SRC），按当前 PyPI 解析"
fi
rm -f "$SEMGREP_PAYLOAD_DIR/pip-freeze.raw"

download_wheels() {
  local out
  # The status has to survive the log trimming below: piping straight into `tail`
  # would make every pip failure look like a success and hide it behind the
  # "no wheels" check several steps later.
  if ! out="$(docker run --rm -v "$SEMGREP_PAYLOAD_DIR:/payload" -v "$SEMGREP_PAYLOAD_DIR/pip-freeze.txt:/freeze.txt:ro" \
    --entrypoint sh "$PIP_IMAGE" -c "
python3 -m pip download --dest /payload/wheels \
  --only-binary=:all: --python-version 3.10 --implementation cp --abi cp310 \
  ${platform_args[*]} $1 \
  -i '$PIP_INDEX_URL' \
  'semgrep==$SEMGREP_VERSION' 2>&1
")"; then
    printf '%s\n' "$out" | tail -6
    return 1
  fi
  printf '%s\n' "$out" | tail -3
}

# A freeze taken from the 3.12 arm cannot be applied to a 3.10 resolve as a whole:
# measured on 2026-10-10 it pins rpds-py==2026.6.3, which publishes no cp310 wheel
# at all, and pip reports that as ResolutionImpossible. Falling back to an
# unconstrained resolve keeps semgrep itself pinned -- what a finding depends on is
# the engine plus the rules, both fixed -- while the rest of the closure follows the
# index. The MANIFEST records which freeze was used and the versions that actually
# shipped, so the difference stays visible after the fact.
if [[ "$have_freeze" == 1 ]]; then
  if download_wheels "-c /freeze.txt"; then
    freeze_used="$PIP_CONSTRAINTS_SRC"
  else
    info "警告：带 constraints 解析失败（冻结的版本可能没有 cp310 wheel），改为不约束重试"
    # The failed resolve leaves a partial set behind; the retry starts from empty.
    rinse "$WHEEL_DIR"
    : > "$SEMGREP_PAYLOAD_DIR/pip-freeze.txt"
    freeze_used="none (docker-arm freeze has no cp310 wheel for every pin)"
    download_wheels ""
  fi
else
  freeze_used="none (no freeze found)"
  download_wheels ""
fi
wheel_count="$(find "$WHEEL_DIR" -name '*.whl' | wc -l)"
[[ "$wheel_count" -gt 0 ]] || die "no wheels were downloaded"
info "wheels: $wheel_count 个, $(du -sh "$WHEEL_DIR" | awk '{print $1}')"
# Recorded before the wheels are unpacked and deleted: these filenames carry both
# the version and the platform tag of everything that ships, which is what a later
# comparison against another arm needs.
find "$WHEEL_DIR" -name '*.whl' -printf '%f\n' | LC_ALL=C sort > "$SEMGREP_PAYLOAD_DIR/wheels.list"

step "安装 jammy python3.10 运行时，并用 pip 把 wheel 装进 pylib"
# One container does both, because they need the same image and the same apt
# state. The order inside it matters: the stdlib is copied out before pip is
# installed, so the copy cannot pick up whatever pip drags in.
#
# The wheels are installed with pip rather than unpacked with zipfile.extractall.
# A hand-rolled extraction was tried first and produced a pylib that looked
# populated but had no semgrep package in it at all, for two reasons that are
# both pip's job to get right: a wheel may carry a scheme directory
# (semgrep-1.177.0.data/purelib/) whose contents belong in the install root
# rather than under a subdirectory, and an executable bit has to be restored
# from the zip entry's external attributes (pip does; zipfile ignores them) or
# semgrep-core lands non-executable.
docker run --rm -v "$SEMGREP_PAYLOAD_DIR:/payload" -e APT_MIRROR="$APT_MIRROR" "$PYTHON_IMAGE" bash -lc '
set -e
sed -i "s|http://archive.ubuntu.com/ubuntu|$APT_MIRROR|g; s|http://security.ubuntu.com/ubuntu|$APT_MIRROR|g" /etc/apt/sources.list
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends python3.10-minimal libpython3.10-stdlib >/dev/null
# The interpreter is installed at its native paths inside the guest too, so no
# PYTHONHOME is needed: the stdlib path is compiled into the binary.
cp -a /usr/bin/python3.10 /payload/rootfs/usr/bin/
cp -a /usr/lib/python3.10 /payload/rootfs/usr/lib/
if [ -e /usr/lib/x86_64-linux-gnu/libpython3.10.so.1.0 ]; then
  mkdir -p /payload/rootfs/usr/lib/x86_64-linux-gnu
  cp -a /usr/lib/x86_64-linux-gnu/libpython3.10.so.1.0 /payload/rootfs/usr/lib/x86_64-linux-gnu/
fi
python3.10 -V
apt-get install -y -qq --no-install-recommends python3-pip >/dev/null
mkdir -p /payload/rootfs/opt/taa/semgrep/pylib
# --no-deps: the closure was already resolved and downloaded above, and letting
# pip resolve again here would try to reach the index for no gain.
# --no-compile: .pyc would be recompiled per boot anyway and only enlarges the
# initrd; the modules are compiled once on the first scan instead.
python3.10 -m pip install --quiet --no-index --no-deps --no-compile \
  --target /payload/rootfs/opt/taa/semgrep/pylib /payload/wheels/*.whl
'
info "python3.10 runtime: $(du -sh "$ROOTFS/usr/lib/python3.10" | awk '{print $1}')"
[[ -x "$PYLIB/semgrep/bin/semgrep-core" ]] || die "semgrep-core missing from the pip install"
info "pylib: $(du -sh "$PYLIB" | awk '{print $1}') (semgrep-core: $(du -h "$PYLIB/semgrep/bin/semgrep-core" | awk '{print $1}'))"
# The wheels are dropped only now: everything that can still fail has failed by
# this point, so a failure above leaves them on disk to be inspected.
rinse "$WHEEL_DIR"

step "补齐 base initrd 缺少的动态库"
# Every ELF object the payload runs is asked for its dependencies; whatever
# resolves to a library the base initrd does not already carry is copied in
# under its soname. RPATH-resolved libraries (semgrep-core's own bin/libs) are
# skipped, which is why they are not duplicated here.
printf '%s\n' "$base_libs" > "$SEMGREP_PAYLOAD_DIR/base-libs.txt"
docker run --rm -v "$SEMGREP_PAYLOAD_DIR:/payload" "$PYTHON_IMAGE" bash -lc '
set -e
cd /payload/rootfs
missing=/payload/missing-libs.txt
: > "$missing"
elfs=$(find opt/taa/semgrep/pylib usr/bin/python3.10 usr/lib/python3.10 -type f \( -name "*.so" -o -name "*.so.*" -o -name "semgrep-core" -o -name "python3.10" \) 2>/dev/null)
for f in $elfs; do
  ldd "$f" 2>/dev/null | awk "/=>/ {print \$3}" | grep "^/" || true
done | sort -u > /payload/all-deps.txt
while read -r lib; do
  base="$(basename "$lib")"
  if ! grep -qxF "$base" /payload/base-libs.txt; then
    echo "$lib" >> "$missing"
  fi
done < /payload/all-deps.txt
'
# The guest rootfs has /lib as a symlink to /usr/lib, so the base's entries are
# compared by basename only: the payload must not ship a second copy of a
# library that is already reachable, whichever of the two paths cpio recorded.
docker run --rm -v "$SEMGREP_PAYLOAD_DIR:/payload" "$PYTHON_IMAGE" bash -lc '
set -e
mkdir -p /payload/rootfs/usr/lib/x86_64-linux-gnu
while read -r lib; do
  cp -aL "$lib" "/payload/rootfs/usr/lib/x86_64-linux-gnu/$(basename "$lib")"
  echo "   + $(basename "$lib")"
done < /payload/missing-libs.txt
'
if [[ -s "$SEMGREP_PAYLOAD_DIR/missing-libs.txt" ]]; then
  info "补入 $(grep -c . "$SEMGREP_PAYLOAD_DIR/missing-libs.txt") 个库"
else
  info "base 已带齐全部依赖库，无需补入"
fi
rm -f "$SEMGREP_PAYLOAD_DIR/all-deps.txt" "$SEMGREP_PAYLOAD_DIR/missing-libs.txt" "$SEMGREP_PAYLOAD_DIR/base-libs.txt"

step "安装 rules、MANIFEST 与 semgrep wrapper"
cp -a "$SEMGREP_RULES_SRC" "$ROOTFS/opt/taa/semgrep/rules"
{
  echo "engine semgrep"
  echo "version $SEMGREP_VERSION"
  echo "python $(basename "$ROOTFS/usr/bin/python3.10") (jammy, glibc 2.35)"
  echo "index $PIP_INDEX_URL"
  echo "constraints ${freeze_used:-none}"
  echo "wheels $(wc -l < "$SEMGREP_PAYLOAD_DIR/wheels.list")"
  cat "$SEMGREP_PAYLOAD_DIR/wheels.list"
  (cd "$ROOTFS/opt/taa/semgrep/rules" && find . -name '*.yaml' | LC_ALL=C sort | xargs sha256sum)
} > "$ROOTFS/opt/taa/semgrep/MANIFEST"
cp "$SEMGREP_PAYLOAD_DIR/pip-freeze.txt" "$ROOTFS/opt/taa/semgrep/pip-freeze.txt"
rm -f "$SEMGREP_PAYLOAD_DIR/pip-freeze.txt"

# The guest's PID 1 gets the kernel's default PATH (/sbin:/usr/sbin:/bin:/usr/bin),
# and TAA resolves the semgrep CLI through PATH, so both entry points are pinned
# there -- symlinks would not do, because the interpreter and the site-packages
# directory have to come with them.
#
# There are two of them, not one: pylib/bin/semgrep dispatches between the OCaml
# CLI (semgrep-core) and the Python one, and the OCaml CLI, when it delegates,
# looks for `pysemgrep` in PATH -- entrypoint.py appends sysconfig's scripts
# directory, which on this rootfs is /usr/local/bin, to PATH for exactly that
# reason. Measured without it: "exception Unix_error: No such file or directory
# execvp pysemgrep". Neither script sets PYTHONPATH itself, since pip would have
# installed them next to a real site-packages tree, which the guest does not have.
install_wrapper() {
  local name="$1"
  cat > "$ROOTFS/usr/local/bin/$name" <<WRAPPER
#!/bin/sh
# Entry point for the semgrep CLI inside the Kata guest. The site-packages
# directory and the interpreter are pinned because the guest has neither on its
# default sys.path or PATH.
PYTHONPATH=/opt/taa/semgrep/pylib
export PYTHONPATH
exec /usr/bin/python3.10 /opt/taa/semgrep/pylib/bin/$name "\$@"
WRAPPER
  chmod 0755 "$ROOTFS/usr/local/bin/$name"
}

install_wrapper semgrep
install_wrapper pysemgrep

step "输出结果摘要"
# Hand the tree back to the invoking user: it was staged by root in a container,
# and root-owned directories would otherwise have to be cleaned up through docker
# on every rebuild.
docker run --rm -v "$SEMGREP_PAYLOAD_DIR:/payload" "$PYTHON_IMAGE" \
  chown -R "$(id -u):$(id -g)" /payload

echo "payload: $SEMGREP_PAYLOAD_DIR"
echo "rootfs 内容（未压缩）:"
du -sm "$ROOTFS"/* | LC_ALL=C sort -k2
echo "合计: $(du -sh "$ROOTFS" | awk '{print $1}')"
echo "文件数: $(find "$ROOTFS" | wc -l)"
