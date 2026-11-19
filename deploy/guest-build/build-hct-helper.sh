#!/usr/bin/env bash
# Build the HCT 3.0.10 helper payload that the CSV2 initrd carries.
#
#   build-hct-helper.sh fetch     download and unpack the pinned HCT deb
#   build-hct-helper.sh build     build taa-hct-helper in a fixed container
#   build-hct-helper.sh payload   assemble deploy/guest-build/hct-payload/
#   build-hct-helper.sh verify    check the payload (glibc, deps, selftest)
#   build-hct-helper.sh selftest  run the known-answer tests on the payload
#
# TAA itself stays a static Go binary (CGO_ENABLED=0). The helper is the only
# process that loads libhct, and TAA starts it through an explicit dynamic
# loader; see internal/hctclient. The payload mirrors the guest paths the
# initrd will carry:
#
#   usr/local/bin/taa-hct-helper
#   opt/hygon/hct/lib64/libhct.so
#   opt/hygon/hct/lib64/libnuma.so.1
#   opt/hygon/hct/MANIFEST
#   etc/hct_config
#
# The package is extracted with `dpkg-deb -x`, which does not run maintainer
# scripts: postinst rewrites /etc and creates symlinks, neither of which belongs
# in an initrd. Only the CAE headers, libhct.so and the version header are read.
#
# The build container pins glibc 2.31 (bullseye) so the helper's GLIBC_*
# references stay below the guest's 2.35. libnuma.so.1 is copied from the same
# container: the base initrd has glibc but no libnuma, and libhct.so needs it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [[ ! -f "$ROOT_DIR/go.mod" ]]; then
  echo "error: repository root not found from $SCRIPT_DIR (no go.mod in $ROOT_DIR)" >&2
  exit 1
fi

# Pinned inputs. The deb is a devkit snapshot build; 3.x and 2.x are ABI
# incompatible, and this repository only ships 3.0.10.
HCT_VERSION="3.0.10"
HCT_DEB_NAME="hct-${HCT_VERSION}-2601d03.x86_64.deb"
HCT_DEB_URL="https://download.sourcefind.cn:65024/file/8/c86-devkit/2026-01-14/hct/${HCT_DEB_NAME}"
HCT_DEB_SHA256="15a8e27462cf936908bbd30473ff521645f8d9c05ba29d8dae947dec3f383091"
HCT_LIB_SHA256="7656c95840161a0f9b539723715027231dea981485137cd1edf103e30b0ccef1"

# The guest base initrd is glibc 2.35. The helper must not reference anything
# newer, or it fails to start inside the guest with a version error that looks
# like a missing library.
GLIBC_MAX="2.35"
BUILD_IMAGE="${HCT_BUILD_IMAGE:-golang:1.22-bullseye}"

# Vendor default config, written into the payload. hct_sw_inst_set selects the
# instruction set the SW backend uses (cis or avx); Phase 0 confirmed CIS on
# this guest, but the value stays overridable for a host that lacks it.
HCT_SW_INST_SET="${HCT_SW_INST_SET:-cis}"

WORK_DIR="${HCT_WORK_DIR:-$SCRIPT_DIR/hct}"
EXTRACT_DIR="$WORK_DIR/root"
DEB_FILE="$WORK_DIR/$HCT_DEB_NAME"
BUILD_DIR="$WORK_DIR/build"
PAYLOAD_DIR="${HCT_PAYLOAD_DIR:-$SCRIPT_DIR/hct-payload}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: $1 is not installed or not in PATH" >&2
    exit 1
  fi
}

sha256_of() {
  sha256sum "$1" | awk '{print $1}'
}

# max_glibc prints the highest GLIBC_<major>.<minor> symbol version a file
# references, or 0 when it references none (a static file).
max_glibc() {
  local max
  max="$(readelf --version-info "$1" 2>/dev/null |
    grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sed 's/^GLIBC_//' | sort -V | tail -n 1)"
  echo "${max:-0}"
}

# version_at_most <actual> <limit> exits 0 when actual <= limit.
version_at_most() {
  [[ "$1" == "0" ]] && return 0
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" == "$2" ]]
}

fetch_deb() {
  require_cmd curl
  require_cmd dpkg-deb
  require_cmd sha256sum

  mkdir -p "$WORK_DIR"
  local have=""
  if [[ -f "$DEB_FILE" ]]; then
    have="$(sha256_of "$DEB_FILE")"
  fi
  if [[ "$have" != "$HCT_DEB_SHA256" ]]; then
    echo "下载 $HCT_DEB_URL"
    curl -fL --retry 3 --retry-delay 2 -o "$DEB_FILE.part" "$HCT_DEB_URL"
    have="$(sha256_of "$DEB_FILE.part")"
    if [[ "$have" != "$HCT_DEB_SHA256" ]]; then
      rm -f "$DEB_FILE.part"
      echo "error: HCT deb sha256 mismatch: got $have, want $HCT_DEB_SHA256" >&2
      exit 1
    fi
    mv "$DEB_FILE.part" "$DEB_FILE"
  else
    echo "复用已下载的 deb: $DEB_FILE"
  fi

  # Extract into an empty directory. `dpkg-deb -x` unpacks data.tar only; the
  # postinst would rewrite /etc and add loader symlinks we do not want.
  rm -rf "$EXTRACT_DIR"
  mkdir -p "$EXTRACT_DIR"
  dpkg-deb -x "$DEB_FILE" "$EXTRACT_DIR"

  local lib="$EXTRACT_DIR/opt/hygon/hct/lib64/libhct.so"
  local header="$EXTRACT_DIR/opt/hygon/hct/include/hct/hct_version.h"
  local cae="$EXTRACT_DIR/opt/hygon/hct/include/hct/cae.h"
  local f
  for f in "$lib" "$header" "$cae"; do
    if [[ ! -f "$f" ]]; then
      echo "error: HCT payload is missing $f" >&2
      exit 1
    fi
  done

  local have_lib
  have_lib="$(sha256_of "$lib")"
  if [[ "$have_lib" != "$HCT_LIB_SHA256" ]]; then
    echo "error: libhct.so sha256 mismatch: got $have_lib, want $HCT_LIB_SHA256" >&2
    exit 1
  fi

  # The header is what the build compiles against; pin the version there too,
  # so a deb whose name says 3.0.10 but whose headers are 2.x cannot slip in.
  if ! { grep -qE '^#define[[:space:]]+VER_MAJOR[[:space:]]+3$' "$header" &&
    grep -qE '^#define[[:space:]]+VER_MINOR[[:space:]]+0$' "$header" &&
    grep -qE '^#define[[:space:]]+VER_PATCH[[:space:]]+10$' "$header"; }; then
    echo "error: unexpected header version in $header:" >&2
    grep -E '^#define[[:space:]]+VER_' "$header" >&2 || true
    exit 1
  fi

  echo "HCT $HCT_VERSION 已解包: $EXTRACT_DIR"
}

build_helper() {
  require_cmd docker
  if [[ ! -f "$EXTRACT_DIR/opt/hygon/hct/lib64/libhct.so" ]]; then
    echo "error: run '$0 fetch' first ($EXTRACT_DIR is empty)" >&2
    exit 1
  fi

  mkdir -p "$BUILD_DIR"
  echo "构建 taa-hct-helper（$BUILD_IMAGE，CGO_ENABLED=1，-tags hct）"

  # The repository is mounted read-only: the container validates the build, it
  # never writes into the checkout. GOWORK=off because go.work is a local,
  # untracked convenience that spans modules not needed by this command.
  docker run --rm \
    -v "$ROOT_DIR":/src:ro \
    -v "$EXTRACT_DIR":/hct:ro \
    -v "$BUILD_DIR":/out \
    -w /src \
    -e CGO_ENABLED=1 \
    -e GOWORK=off \
    -e GOFLAGS=-mod=mod \
    -e CGO_CFLAGS=-I/hct/opt/hygon/hct/include \
    -e CGO_LDFLAGS=-L/hct/opt/hygon/hct/lib64 \
    "$BUILD_IMAGE" bash -euo pipefail -c '
      apt-get update -qq
      apt-get install -y -qq libnuma-dev >/dev/null
      go build -tags hct -trimpath -buildvcs=false \
        -ldflags "-s -w" \
        -o /out/taa-hct-helper ./cmd/taa-hct-helper
      # libhct.so NEEDEDs libnuma.so.1, which the base initrd does not carry.
      # Copy it out of this container so the payload stays on glibc 2.31.
      cp /usr/lib/x86_64-linux-gnu/libnuma.so.1 /out/libnuma.so.1
    '

  local f
  for f in "$BUILD_DIR/taa-hct-helper" "$BUILD_DIR/libnuma.so.1"; do
    if [[ ! -e "$f" ]]; then
      echo "error: the build container did not produce $f" >&2
      exit 1
    fi
  done
  echo "helper: $BUILD_DIR/taa-hct-helper ($(stat -c %s "$BUILD_DIR/taa-hct-helper") bytes)"
}

# run_helper <libdir> <args...> starts the helper through the guest's loader,
# which is also how TAA starts it (no LD_LIBRARY_PATH inheritance, no rpath).
run_helper() {
  local libdir="$1"
  shift
  env -u LD_PRELOAD -u LD_AUDIT -u LD_LIBRARY_PATH \
    HCT_LOG_LEVEL=error \
    "$HCT_LOADER" --library-path "$libdir" "$@"
}

payload_paths() {
  local dir="$1"
  local f
  for f in \
    "usr/local/bin/taa-hct-helper" \
    "opt/hygon/hct/lib64/libhct.so" \
    "opt/hygon/hct/lib64/libnuma.so.1" \
    "opt/hygon/hct/MANIFEST" \
    "etc/hct_config"; do
    if [[ ! -e "$dir/$f" ]]; then
      echo "error: payload is missing $f" >&2
      echo "hint: run '$0 payload'" >&2
      exit 1
    fi
  done
}

write_hct_config() {
  local dst="$1"
  mkdir -p "$(dirname "$dst")"
  cat >"$dst" <<EOF
{
    "filekey_index" : 1,
    "filekey_auth" : "11111111",
    "hct_log_level" : "error",
    "hct_sw_inst_set" : "$HCT_SW_INST_SET",
    "balance_policy" : "auto"
}
EOF
  chmod 0644 "$dst"
}

selftest_payload() {
  local dir="${1:-$PAYLOAD_DIR}"
  payload_paths "$dir"

  local libdir="$dir/opt/hygon/hct/lib64"
  local helper="$dir/usr/local/bin/taa-hct-helper"

  # hct_get_version() returns "hct-3.0.10-2601d03-": the release and build id in
  # one string, with a "hct-" prefix that the prefix check has to tolerate. The
  # Go client matches it by components for the same reason.
  local version
  version="$(run_helper "$libdir" "$helper" --version)"
  case "$version" in
    "$HCT_VERSION"*|"hct-$HCT_VERSION"*) ;;
    *)
      echo "error: helper reports libhct version '$version', want a $HCT_VERSION build" >&2
      exit 1
      ;;
  esac
  echo "hct_get_version: $version"

  # The KAT includes a tampered-tag case, so libhct logs one expected
  # "[error] ... verify fail" line while the selftest still passes.
  echo "运行自检（含坏 tag 拒绝用例，libhct 的 verify fail 日志是预期输出）"
  local out
  out="$(run_helper "$libdir" "$helper" --selftest)"
  printf '%s\n' "$out" | sed 's/^/  /'
  if ! printf '%s\n' "$out" | grep -q 'SELFTEST PASS'; then
    echo "error: helper selftest did not pass" >&2
    exit 1
  fi
}

verify_payload() {
  local dir="${1:-$PAYLOAD_DIR}"
  payload_paths "$dir"
  require_cmd readelf
  require_cmd file

  local helper="$dir/usr/local/bin/taa-hct-helper"
  local lib="$dir/opt/hygon/hct/lib64/libhct.so"
  local f

  echo "校验 helper 链接属性"
  if [[ ! -x "$helper" ]]; then
    echo "error: helper is not executable: $helper" >&2
    exit 1
  fi
  if [[ "$(file -b "$helper")" != *"dynamically linked"* ]]; then
    echo "error: helper is not dynamically linked: $(file -b "$helper")" >&2
    exit 1
  fi
  if ! readelf -l "$helper" | grep -q 'interpreter'; then
    echo "error: helper has no PT_INTERP; it cannot be started through the loader" >&2
    exit 1
  fi
  if ! readelf -d "$helper" | grep -q 'libhct.so'; then
    echo "error: helper does not link libhct.so" >&2
    exit 1
  fi

  # A 2.x library anywhere in the payload is the one failure mode that cannot
  # be caught at runtime: 3.x and 2.x share SONAMEs and are ABI incompatible.
  local stray
  stray="$(find "$dir" \( -name 'libhct*' -o -name 'hysdf*' -o -name 'hypsp*' \) \
    ! -path '*/opt/hygon/hct/lib64/libhct.so' -print)"
  if [[ -n "$stray" ]]; then
    echo "error: payload carries unexpected HCT-family files:" >&2
    printf '%s\n' "$stray" >&2
    exit 1
  fi
  for f in engines-1.1 engines-3 hct_test hct_speed hctd tkm sdf; do
    if [[ -e "$dir/$f" ]] || find "$dir" -maxdepth 6 -name "$f" -print -quit | grep -q .; then
      echo "error: payload carries $f, which the initrd must not ship" >&2
      exit 1
    fi
  done

  echo "校验 GLIBC 版本上限（<= $GLIBC_MAX）"
  local max
  max="$(max_glibc "$helper")"
  echo "  helper: GLIBC_$max"
  if ! version_at_most "$max" "$GLIBC_MAX"; then
    echo "error: helper references GLIBC_$max, newer than the guest's $GLIBC_MAX" >&2
    exit 1
  fi
  max="$(max_glibc "$lib")"
  echo "  libhct.so: GLIBC_$max"
  if ! version_at_most "$max" "$GLIBC_MAX"; then
    echo "error: libhct.so references GLIBC_$max, newer than the guest's $GLIBC_MAX" >&2
    exit 1
  fi
  max="$(max_glibc "$dir/opt/hygon/hct/lib64/libnuma.so.1")"
  echo "  libnuma.so.1: GLIBC_$max"
  if ! version_at_most "$max" "$GLIBC_MAX"; then
    echo "error: libnuma.so.1 references GLIBC_$max, newer than the guest's $GLIBC_MAX" >&2
    exit 1
  fi

  echo "校验 MANIFEST"
  if ! grep -q "^hct_version=$HCT_VERSION$" "$dir/opt/hygon/hct/MANIFEST"; then
    echo "error: MANIFEST does not record HCT $HCT_VERSION" >&2
    exit 1
  fi
  if ! grep -q "^deb_sha256=$HCT_DEB_SHA256$" "$dir/opt/hygon/hct/MANIFEST"; then
    echo "error: MANIFEST does not record the pinned deb sha256" >&2
    exit 1
  fi
  if ! grep -q "^libhct_sha256=$HCT_LIB_SHA256$" "$dir/opt/hygon/hct/MANIFEST"; then
    echo "error: MANIFEST does not record the pinned libhct sha256" >&2
    exit 1
  fi
  if [[ "$(sha256_of "$lib")" != "$HCT_LIB_SHA256" ]]; then
    echo "error: packaged libhct.so does not match the pinned sha256" >&2
    exit 1
  fi
  if [[ "$(sha256_of "$helper")" != "$(sed -n 's/^helper_sha256=//p' "$dir/opt/hygon/hct/MANIFEST")" ]]; then
    echo "error: packaged helper does not match its MANIFEST sha256" >&2
    exit 1
  fi

  selftest_payload "$dir"
  echo "payload 校验通过: $dir"
}

make_payload() {
  require_cmd sha256sum
  local lib="$EXTRACT_DIR/opt/hygon/hct/lib64/libhct.so"
  if [[ ! -f "$lib" || ! -x "$BUILD_DIR/taa-hct-helper" ]]; then
    echo "error: run '$0 fetch' and '$0 build' first" >&2
    exit 1
  fi

  rm -rf "$PAYLOAD_DIR"
  mkdir -p "$PAYLOAD_DIR/usr/local/bin" "$PAYLOAD_DIR/opt/hygon/hct/lib64" \
    "$PAYLOAD_DIR/etc"
  install -m 0755 "$BUILD_DIR/taa-hct-helper" "$PAYLOAD_DIR/usr/local/bin/taa-hct-helper"
  install -m 0755 "$lib" "$PAYLOAD_DIR/opt/hygon/hct/lib64/libhct.so"
  install -m 0755 "$BUILD_DIR/libnuma.so.1" "$PAYLOAD_DIR/opt/hygon/hct/lib64/libnuma.so.1"
  write_hct_config "$PAYLOAD_DIR/etc/hct_config"

  # The version comes from the library itself, not from the deb name: the
  # runtime check compares the same string.
  local libdir="$PAYLOAD_DIR/opt/hygon/hct/lib64"
  local version
  version="$(run_helper "$libdir" "$PAYLOAD_DIR/usr/local/bin/taa-hct-helper" --version)"

  local helper_sha libnuma_sha
  helper_sha="$(sha256_of "$PAYLOAD_DIR/usr/local/bin/taa-hct-helper")"
  libnuma_sha="$(sha256_of "$PAYLOAD_DIR/opt/hygon/hct/lib64/libnuma.so.1")"
  cat >"$PAYLOAD_DIR/opt/hygon/hct/MANIFEST" <<EOF
hct_version=$HCT_VERSION
hct_build=$version
hct_sw_inst_set=$HCT_SW_INST_SET
deb_url=$HCT_DEB_URL
deb_sha256=$HCT_DEB_SHA256
libhct_sha256=$HCT_LIB_SHA256
libnuma_sha256=$libnuma_sha
libnuma_source=$BUILD_IMAGE:/usr/lib/x86_64-linux-gnu/libnuma.so.1
helper_sha256=$helper_sha
helper_max_glibc=$(max_glibc "$PAYLOAD_DIR/usr/local/bin/taa-hct-helper")
hctd_required=no
built=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
  chmod 0644 "$PAYLOAD_DIR/opt/hygon/hct/MANIFEST"

  # hctd_required=no is a Phase 0 conclusion, not an assumption: the full
  # operation set (SM2/SM3/HMAC/SM4-GCM, KAT included) was exercised in a
  # process with no hctd and no hct.ko. If that ever stops holding, the helper
  # selftest fails on a clean host and this line has to be revisited.

  verify_payload "$PAYLOAD_DIR"

  local payload_files payload_mib
  read -r payload_files payload_mib < <(
    find "$PAYLOAD_DIR" -mindepth 1 -type f -printf '%s\n' |
      awk '{n++; s += $1} END {printf "%d %.1f\n", n, s / 1048576}'
  )
  echo "HCT payload: $PAYLOAD_DIR, ${payload_mib} MiB / ${payload_files} 个文件"
}

usage() {
  cat >&2 <<EOF
usage: $0 <fetch|build|payload|verify|selftest> [payload-dir]

  fetch      download $HCT_DEB_NAME, verify its sha256, unpack it into $EXTRACT_DIR
  build      build taa-hct-helper in $BUILD_IMAGE and copy libnuma.so.1 next to it
  payload    assemble $PAYLOAD_DIR (helper, libhct, libnuma, hct_config, MANIFEST)
  verify     check a payload: dynamic helper, libhct dependency, GLIBC <= $GLIBC_MAX,
             no 2.x residue, MANIFEST hashes, and the known-answer tests
  selftest   run only the known-answer tests against a payload

Environment overrides:
  HCT_WORK_DIR=$WORK_DIR
  HCT_PAYLOAD_DIR=$PAYLOAD_DIR
  HCT_BUILD_IMAGE=$BUILD_IMAGE
  HCT_LOADER=$HCT_LOADER
  HCT_SW_INST_SET=$HCT_SW_INST_SET
EOF
}

HCT_LOADER="${HCT_LOADER:-/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2}"

command="${1:-}"
case "$command" in
  fetch) fetch_deb ;;
  build) build_helper ;;
  payload) make_payload ;;
  verify) verify_payload "${2:-}" ;;
  selftest) selftest_payload "${2:-}" ;;
  *) usage; exit 2 ;;
esac
