#!/usr/bin/env bash
# Offline tests for deploy-taa-vm.sh.
#
# Scope, stated honestly: this covers the parts that can be exercised without the
# host. The containerd handler stripper is the highest-value one -- it is the only
# code in the flow that rewrites a config file the whole node depends on, and a
# bug there would take other people's Pods down. The remote teardown itself is
# NOT covered here; it is only ever run through `delete --dry-run` first.
#
#   ./test-deploy-taa-vm.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER="$SCRIPT_DIR/deploy-taa-vm.sh"
BUILD="$SCRIPT_DIR/build-initrd.sh"

tmp_dir="$(mktemp -d /tmp/test-deploy-taa-vm.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT

failures=0
check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    failures=$((failures + 1))
  fi
}

check_contains() {
  local name="$1" needle="$2" haystack="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name (missing: $needle)" >&2
    failures=$((failures + 1))
  fi
}

# ── 1. print-config is sourceable and round-trips ────────────────────────────
config="$(REMOTE_USER=root TEST_POD_ANNOTATIONS='{"a.b":"c d"}' "$BUILD" print-config)"
eval "$config"
check "print-config: REMOTE_USER override survives" "root" "$REMOTE_USER"
check "print-config: JSON with a space survives eval" '{"a.b":"c d"}' "$TEST_POD_ANNOTATIONS"

default_config="$("$BUILD" print-config)"
eval "$default_config"
check "print-config: default annotations are an empty object" "{}" "$TEST_POD_ANNOTATIONS"
check "print-config: default handler" "kata-qemu-csv2-taa" "$RUNTIME_HANDLER"

# ── 2. the containerd handler stripper ───────────────────────────────────────
#
# Extract the program between the marker comments the script carries for exactly
# this purpose, then run it against a fixture shaped like the host config.
block="$(sed -n '/# BEGIN containerd-handler-strip/,/# END containerd-handler-strip/p' "$DRIVER")"
stripper="$tmp_dir/strip.py"
printf '%s\n' "$block" | sed -n "/<<'PY'/,/^PY\$/p" | sed '1d;$d' > "$stripper"
if [[ ! -s "$stripper" ]]; then
  echo "FAIL could not extract the stripper from $DRIVER" >&2
  exit 1
fi
if ! python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$stripper"; then
  echo "FAIL extracted stripper is not valid python" >&2
  exit 1
fi
echo "ok   extracted the stripper ($(wc -l < "$stripper") lines)"

cat > "$tmp_dir/config.toml" <<'TOML'
version = 2

[plugins."io.containerd.grpc.v1.cri"]
  sandbox_image = "registry/pause:3.9"

[plugins."io.containerd.grpc.v1.cri".containerd]
  snapshotter = "overlayfs"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."kata-qemu-csv2"]
  runtime_type = "io.containerd.kata-qemu-csv2.v2"
  privileged_without_host_devices = true

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."kata-qemu-csv2".options]
  ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."kata-qemu-csv2-taa"]
  runtime_type = "io.containerd.kata-qemu-csv2.v2"
  runtime_path = "/opt/kata/bin/containerd-shim-kata-v2"
  privileged_without_host_devices = true
  pod_annotations = ["io.katacontainers.*"]
  snapshotter = "nydus"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."kata-qemu-csv2-taa".options]
  ConfigPath = "/etc/kata-containers/configuration-qemu-csv2-taa.toml"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."kata-qemu-hygon-dcu-csv2"]
  runtime_type = "io.containerd.kata-qemu-hygon-dcu-csv2.v2"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."kata-qemu-hygon-dcu-csv2".options]
  ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration-qemu-hygon-dcu-csv2.toml"
TOML
cp "$tmp_dir/config.toml" "$tmp_dir/original.toml"

python3 "$stripper" "$tmp_dir/config.toml" "kata-qemu-csv2-taa"
result="$(cat "$tmp_dir/config.toml")"

check_contains "stripper: removes the handler's own table" "" "$result"
if [[ "$result" == *"kata-qemu-csv2-taa"* ]]; then
  echo "FAIL stripper: our handler still appears in the output" >&2
  failures=$((failures + 1))
else
  echo "ok   stripper: our handler is gone, options table included"
fi
check_contains "stripper: keeps the shipped handler" 'runtimes."kata-qemu-csv2"]' "$result"
check_contains "stripper: keeps the shipped handler's options" 'configuration-qemu-csv2.toml' "$result"
check_contains "stripper: keeps an unrelated later handler" 'kata-qemu-hygon-dcu-csv2"]' "$result"
check_contains "stripper: keeps unrelated plugin settings" 'sandbox_image' "$result"
check_contains "stripper: keeps version = 2" 'version = 2' "$result"

# Removing a handler that is not there must be a no-op: the script relies on
# that to decide whether containerd needs a restart at all.
cp "$tmp_dir/original.toml" "$tmp_dir/noop.toml"
python3 "$stripper" "$tmp_dir/noop.toml" "kata-does-not-exist"
if cmp -s "$tmp_dir/noop.toml" "$tmp_dir/original.toml"; then
  echo "ok   stripper: absent handler is a byte-for-byte no-op"
else
  echo "FAIL stripper: absent handler changed the file" >&2
  diff "$tmp_dir/original.toml" "$tmp_dir/noop.toml" >&2 || true
  failures=$((failures + 1))
fi

# ...and removing the last block must not leave a trailing blank line, or every
# later comparison against the backup file would differ for no reason.
tail -c 1 "$tmp_dir/config.toml" | od -c | grep -q '\\n' &&
  echo "ok   stripper: output ends with a single newline" ||
  { echo "FAIL stripper: output does not end with a newline" >&2; failures=$((failures + 1)); }

# ── 3. guards that must be present in the teardown ───────────────────────────
#
# These are string checks, not behavioural ones: they prove the guard was not
# dropped while editing, which is the realistic failure mode.
driver_src="$(cat "$DRIVER")"
check_contains "guard: refuses the shipped kata config" 'REMOTE_KATA_CONFIG 指向出厂 Kata 配置' "$driver_src"
check_contains "guard: refuses the shipped runtime handler" 'RUNTIME_HANDLER 是出厂 handler' "$driver_src"
check_contains "guard: refuses a shared bundle directory" 'REMOTE_BUNDLE_DIR 指向共享目录' "$driver_src"
check_contains "guard: refuses a runtime still in use" '仍被以下 Pod 使用' "$driver_src"
check_contains "guard: verifies the original kata config afterwards" '出厂 Kata 配置未变' "$driver_src"
check_contains "guard: verifies the base initrd afterwards" 'base initrd 未变' "$driver_src"
check_contains "delete defaults to dry-run-able, mutation goes through one point" 'dry-run: %s' "$driver_src"

# ── 4. argv handling ────────────────────────────────────────────────────────
"$DRIVER" help >/dev/null 2>&1 && echo "ok   help exits 0" ||
  { echo "FAIL help did not exit 0" >&2; failures=$((failures + 1)); }
"$DRIVER" bogus >/dev/null 2>&1 && { echo "FAIL unknown command exited 0" >&2; failures=$((failures + 1)); } ||
  echo "ok   unknown command exits non-zero"
"$DRIVER" delete --bogus >/dev/null 2>&1 && { echo "FAIL bad delete option exited 0" >&2; failures=$((failures + 1)); } ||
  echo "ok   bad delete option exits non-zero"

# ── 5. preflight refuses before touching the host ───────────────────────────
#
# A missing base must be caught here, with the hint, and without an ssh attempt.
out="$(BASE_INITRD="$tmp_dir/absent.img" "$DRIVER" build 2>&1 || true)"
check_contains "preflight: explains a missing base initrd" "fetch-base" "$out"

dynamic_bin="$tmp_dir/taa-dynamic"
printf '#!/bin/sh\n' > "$dynamic_bin"
mkdir -p "$tmp_dir/fake-tree/bin"
cp /bin/true "$tmp_dir/fake-tree/bin/taa"
out="$(TAA_SRC="$tmp_dir/fake-tree/bin/taa" BASE_INITRD="$tmp_dir/absent.img" "$DRIVER" build 2>&1 || true)"
check_contains "preflight: still fails on the missing base first" "base initrd 缺失" "$out"

echo
if [[ "$failures" -eq 0 ]]; then
  echo "all checks passed"
else
  echo "$failures check(s) failed" >&2
  exit 1
fi
