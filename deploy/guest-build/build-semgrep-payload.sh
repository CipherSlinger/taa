#!/usr/bin/env bash
#
# build-semgrep-payload.sh -- build the Tier 1 semgrep payload that
# build-initrd.sh injects into the Kata CSV2 initrd.
#
# Why this is a script and not a committed directory: the payload is a Python
# runtime plus ~310 MiB of third-party wheels, none of which belongs in git.
# This file is the recipe; semgrep-payload/ is derived state and gitignored.
#
# Why Python 3.12: this interpreter is also the one model runtimeConfig
# commands run on, and models are now pushed with cp312 wheels; semgrep itself
# declares Requires-Python >=3.10, so one 3.12 satisfies both. What constrains
# the source is the guest's glibc: the guest rootfs is Ubuntu 22.04 (glibc 2.35),
# so the interpreter may reference at most GLIBC_2.35. Measured with readelf
# --version-info: Debian bookworm's python3.12 stops exactly at 2.35, which
# leaves no margin against the guest's own ceiling, while Debian bullseye's
# stops at 2.30. Hence the official image on bullseye.
#
# Two other sources were measured on 2026-11-09 and rejected: python-build-
# standalone needs no build step but its GitHub release asset (64.7 MB) came
# down at ~10 KB/s here and stalled, and deadsnakes' jammy PPA arrives over
# launchpad at 18 KB/s and publishes no -minimal/-stdlib split -- an apt install
# from it had not finished after 25 minutes, so it is not a usable build input
# from here. The image pulls from the local Docker mirror in seconds.
#
# The wheels follow their own constraint: semgrep 1.177.0 ships a
# manylinux_2_34 wheel, i.e. one that needs glibc >= 2.34 and therefore runs on
# the guest's 2.35. semgrep-core itself needs at most GLIBC_2.34, and it carries
# its own dependencies (libstdc++, libcurl, ...) in semgrep/bin/libs, so only
# libc comes from the guest.
#
# Output layout mirrors the guest rootfs, so build-initrd.sh can copy it in
# with a single `cp -a`:
#
#   semgrep-payload/rootfs/usr/local/bin/python3.12       (interpreter)
#   semgrep-payload/rootfs/usr/local/bin/python[3]        (symlinks to it)
#   semgrep-payload/rootfs/usr/local/lib/python3.12/**    (stdlib + lib-dynload)
#   semgrep-payload/rootfs/usr/local/lib/libpython3.12*   (the shared build)
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
#   SEMGREP_VERSION      1.177.0 (keep in step with deploy.sh --scan-engine semgrep)
#   SEMGREP_RULES_SRC    $ROOT_DIR/teeaudit/models/audit/semgrep/rules
#   SEMGREP_PAYLOAD_DIR  $SCRIPT_DIR/semgrep-payload
#   BASE_INITRD          $SCRIPT_DIR/base/kata-containers-initrd-confidential-csv.img
#   PYTHON_IMAGE         python:3.12-slim-bullseye  (glibc 2.31, shared build)
#   PIP_IMAGE            taa-env:slim-v2    (any image with pip; never modified)
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
SEMGREP_RULES_SRC="${SEMGREP_RULES_SRC:-$ROOT_DIR/teeaudit/models/audit/semgrep/rules}"
SEMGREP_PAYLOAD_DIR="${SEMGREP_PAYLOAD_DIR:-$SCRIPT_DIR/semgrep-payload}"
BASE_INITRD="${BASE_INITRD:-$SCRIPT_DIR/base/kata-containers-initrd-confidential-csv.img}"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-slim-bullseye}"
PYTHON_VERSION="${PYTHON_VERSION:-3.12}"
PYTHON_ABI="${PYTHON_ABI:-cp312}"
# The official python images install under /usr/local; the payload keeps that
# layout, which is what lets the copied binary find its stdlib without
# PYTHONHOME (the prefix is compiled in).
PYTHON_PREFIX=/usr/local
PYTHON_BIN="python${PYTHON_VERSION}"
PIP_IMAGE="${PIP_IMAGE:-taa-env:slim-v2}"
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

step "下载 semgrep $SEMGREP_VERSION 的 cp312 wheel（含完整依赖闭包）"
# --only-binary --python-version --platform is what makes any host download this
# interpreter's closure: pip resolves against the tags given instead of the
# interpreter it runs on, so the payload does not depend on the build host's
# Python.
platform_args=()
for p in "${WHEEL_PLATFORMS[@]}"; do platform_args+=(--platform "$p"); done

# The TAA container's pip-freeze pins the exact versions its semgrep arm was built
# and measured with. Reusing it as constraints keeps the guest arm comparable to
# the arm the evidence was collected on, so a differing verdict can be attributed
# to the guest rather than to a different dependency set. The semgrep line itself
# is dropped: pip rejects a package that is both a requirement and an equal
# constraint.
#
# The freeze was recorded at image build time in the running container's writable
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
  --only-binary=:all: --python-version $PYTHON_VERSION --implementation cp --abi $PYTHON_ABI \
  ${platform_args[*]} $1 \
  -i '$PIP_INDEX_URL' \
  'semgrep==$SEMGREP_VERSION' 2>&1
")"; then
    printf '%s\n' "$out" | tail -6
    return 1
  fi
  printf '%s\n' "$out" | tail -3
}

# The freeze now describes a 3.12 arm, the same interpreter generation this
# payload ships, so the constraint is expected to apply as a whole and make the
# guest arm comparable to the measured one. It is still not a hard requirement: a
# pin can lack a wheel for this tag set, and pip reports that as
# ResolutionImpossible. Falling back to an unconstrained resolve keeps semgrep
# itself pinned -- what a finding depends on is the engine plus the rules, both
# fixed -- while the rest of the closure follows the index. The MANIFEST records
# which freeze was used and the versions that actually shipped, so the difference
# stays visible after the fact.
if [[ "$have_freeze" == 1 ]]; then
  if download_wheels "-c /freeze.txt"; then
    freeze_used="$PIP_CONSTRAINTS_SRC"
  else
    info "警告：带 constraints 解析失败（冻结的版本可能没有 cp312 wheel），改为不约束重试"
    # The failed resolve leaves a partial set behind; the retry starts from empty.
    rinse "$WHEEL_DIR"
    : > "$SEMGREP_PAYLOAD_DIR/pip-freeze.txt"
    freeze_used="none (docker-arm freeze has no cp312 wheel for every pin)"
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

step "复制 python$PYTHON_VERSION 运行时，并用 pip 把 wheel 装进 pylib"
# Nothing is installed in this container: the interpreter is copied out of the
# image it was built in, which is why this step needs no apt, no PPA and no
# network beyond the image pull.
#
# The wheels are installed with pip rather than unpacked with zipfile.extractall.
# A hand-rolled extraction was tried first and produced a pylib that looked
# populated but had no semgrep package in it at all, for two reasons that are
# both pip's job to get right: a wheel may carry a scheme directory
# (semgrep-1.177.0.data/purelib/) whose contents belong in the install root
# rather than under a subdirectory, and an executable bit has to be restored
# from the zip entry's external attributes (pip does; zipfile ignores them) or
# semgrep-core lands non-executable.
docker run --rm -v "$SEMGREP_PAYLOAD_DIR:/payload" \
  -e PYVER="$PYTHON_VERSION" -e PYBIN="$PYTHON_BIN" -e PREFIX="$PYTHON_PREFIX" \
  -e PLATFORMS="${platform_args[*]}" "$PYTHON_IMAGE" bash -lc '
set -e
mkdir -p "/payload/rootfs$PREFIX/bin" "/payload/rootfs$PREFIX/lib"
cp -a "$PREFIX/bin/$PYBIN" "/payload/rootfs$PREFIX/bin/"
cp -a "$PREFIX/lib/python$PYVER" "/payload/rootfs$PREFIX/lib/"
# The official images are a shared build: the real interpreter code lives in
# libpython, and without it the copied binary starts and then cannot load its
# own modules. A static build would need this branch revisited, so say so.
libpython="$PREFIX/lib/libpython$PYVER.so.1.0"
if [ ! -e "$libpython" ]; then
  echo "error: $PYBIN is not a shared build (no $libpython); the payload copy expects one" >&2
  exit 1
fi
cp -a "$libpython" "/payload/rootfs$PREFIX/lib/"
"$PYBIN" -V
mkdir -p /payload/rootfs/opt/taa/semgrep/pylib
# --platform/--only-binary: the wheels are manylinux_2_34, while this host is
# glibc 2.31, so pip would reject them as "not a supported wheel on this
# platform" even though the guest (2.35) can load them. Installing by the tag
# they were resolved for above is exactly right here.
# --no-deps: the closure was already resolved and downloaded above, and letting
# pip resolve again here would try to reach the index for no gain.
# --no-compile: .pyc would be recompiled per boot anyway and only enlarges the
# initrd; the modules are compiled once on the first scan instead.
"$PYBIN" -m pip install --quiet --no-index --no-deps --no-compile \
  --only-binary=:all: $PLATFORMS \
  --target /payload/rootfs/opt/taa/semgrep/pylib /payload/wheels/*.whl
# pip rides along in the stdlib shipped by the image and nothing in the guest
# ever runs it; it is ~7 MiB of initrd for no function.
rm -rf "/payload/rootfs$PREFIX/lib/python$PYVER/site-packages/pip" \
       "/payload/rootfs$PREFIX/lib/python$PYVER/site-packages/pip-"*
'
info "python runtime: $(du -sh "$ROOTFS$PYTHON_PREFIX/lib/python$PYTHON_VERSION" | awk '{print $1}')"
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
docker run --rm -v "$SEMGREP_PAYLOAD_DIR:/payload" -e PYVER="$PYTHON_VERSION" \
  "$PYTHON_IMAGE" bash -lc '
set -e
cd /payload/rootfs
missing=/payload/missing-libs.txt
: > "$missing"
elfs=$(find opt/taa/semgrep/pylib usr/local/bin/python$PYVER usr/local/lib/python$PYVER usr/local/lib/libpython$PYVER.so.1.0 -type f \( -name "*.so" -o -name "*.so.*" -o -name "semgrep-core" -o -name "python$PYVER" \) 2>/dev/null)
for f in $elfs; do
  ldd "$f" 2>/dev/null | awk "/=>/ {print \$3}" | grep "^/" || true
done | sort -u > /payload/all-deps.txt
# The interpreter is a shared build and its RUNPATH is $ORIGIN/../lib, so the
# libpython already staged next to it is reachable without help. ldd still
# reports it as a dependency under the multiarch dir of the build container (the
# scan runs on relative paths, so $ORIGIN resolves there), which would add a
# second, identical 6.5 MiB copy to the initrd.
find usr/local/lib -maxdepth 1 -name "*.so.*" -printf "%f\n" > /payload/payload-libs.txt 2>/dev/null || true
while read -r lib; do
  base="$(basename "$lib")"
  if ! grep -qxF "$base" /payload/base-libs.txt && ! grep -qxF "$base" /payload/payload-libs.txt; then
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
rm -f "$SEMGREP_PAYLOAD_DIR/all-deps.txt" "$SEMGREP_PAYLOAD_DIR/missing-libs.txt" \
  "$SEMGREP_PAYLOAD_DIR/base-libs.txt" "$SEMGREP_PAYLOAD_DIR/payload-libs.txt"

step "安装 rules、MANIFEST 与 semgrep wrapper"
cp -a "$SEMGREP_RULES_SRC" "$ROOTFS/opt/taa/semgrep/rules"
{
  echo "engine semgrep"
  echo "version $SEMGREP_VERSION"
  echo "python $PYTHON_BIN ($PYTHON_IMAGE, glibc 2.30 ceiling)"
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
exec /usr/local/bin/$PYTHON_BIN /opt/taa/semgrep/pylib/bin/$name "\$@"
WRAPPER
  chmod 0755 "$ROOTFS/usr/local/bin/$name"
}

install_wrapper semgrep
install_wrapper pysemgrep

# Model runtimeConfig commands and third-party scripts say `python` or
# `python3`, never `python3.12`. Both names are shipped here, in the payload
# rather than in the TAA member, so they exist exactly when the interpreter does
# (the plain seed has no Python at all, and a dangling link would turn "python is
# not installed" into "python exists but cannot run").
#
# /usr/local/bin is on the PATH taa-init hands to TAA and its children; /usr/bin
# covers a command that sets its own PATH or a `#!/usr/bin/env python3` script
# resolved against the distribution default. The links are relative so they stay
# valid wherever the tree is unpacked -- cpio stores the target verbatim.
mkdir -p "$ROOTFS/usr/local/bin" "$ROOTFS/usr/bin"
ln -sfn "$PYTHON_BIN" "$ROOTFS/usr/local/bin/python3"
ln -sfn "$PYTHON_BIN" "$ROOTFS/usr/local/bin/python"
ln -sfn "../local/bin/$PYTHON_BIN" "$ROOTFS/usr/bin/python3"
ln -sfn "../local/bin/$PYTHON_BIN" "$ROOTFS/usr/bin/python"

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
