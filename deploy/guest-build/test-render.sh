#!/usr/bin/env bash
# Offline tests for the local renderer used by `render` and `launch`.
#
# The point of rendering on the build host is that the same files can be
# installed by launch and handed to someone else as a delivery package. If the
# renderer is wrong, both paths are wrong in the same way, so it is tested here
# with fixtures and a PATH whose ssh/scp fail: every test below must pass
# without touching a host.
#
#   ./test-render.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD="$SCRIPT_DIR/build-initrd.sh"
DRIVER="$ROOT_DIR/deploy-taa-vm.sh"
RENDER="$SCRIPT_DIR/render/render.py"

tmp_dir="$(mktemp -d /tmp/test-render.XXXXXX)"
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

check_absent() {
  local name="$1" needle="$2" haystack="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name (unexpected: $needle)" >&2
    failures=$((failures + 1))
  fi
}

# ssh/scp must never run during rendering. Wrappers that record the call and
# fail hard make that visible instead of silently succeeding.
fakebin="$tmp_dir/fakebin"
mkdir -p "$fakebin"
for tool in ssh scp; do
  cat > "$fakebin/$tool" <<EOF
#!/bin/sh
touch "$tmp_dir/\$0.called"
exit 99
EOF
  chmod +x "$fakebin/$tool"
done
PATH="$fakebin:$PATH"

# ── fixtures ────────────────────────────────────────────────────────────────
template="$tmp_dir/configuration-qemu-csv2.toml"
cat > "$template" <<'TOML'
# Shipped Kata CSV2 config, trimmed to what the renderer reads.
[hypervisor.qemu]
kernel = "/usr/share/kata-containers/vmlinuz.container"
image = "/usr/share/kata-containers/kata-containers.img"
initrd = "/usr/share/kata-containers/kata-containers-initrd.img"
firmware = "/usr/share/ovmf/OVMF.fd"
kernel_params = "console=ttyS0 init=/sbin/init rdinit=/old/init quiet"
enable_debug = true
disable_guest_selinux = true
default_vcpus = 3

[hypervisor.qemu.rate_limiter]
burst = 10

[agent.kata]
kernel_params = "must not be touched"
debug_console_enabled = true
TOML

# Small measurement inputs; the real digest vectors are checked separately
# against the base assets when they are present.
printf 'fixture-ovmf\n' > "$tmp_dir/fixture-ovmf.fd"
printf 'fixture-kernel\n' > "$tmp_dir/fixture-vmlinuz"
printf 'fixture-initrd\n' > "$tmp_dir/fixture-initrd.img"

bundle="/opt/kata/share/kata-containers/taa-csv2"
common_env=(
  KATA_CONFIG_TEMPLATE="$template"
  REMOTE_BUNDLE_DIR="$bundle"
  REMOTE_KATA_CONFIG_SRC=/opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml
  REMOTE_KATA_CONFIG=/etc/kata-containers/configuration-qemu-csv2-taa.toml
  RUNTIME_HANDLER=kata-qemu-csv2-taa
  TEST_POD_NAME=test-kata-csv2-taa
  TEST_NODE_NAME=fixture-node
  TEST_POD_ANNOTATIONS='{"io.katacontainers.config.hypervisor.cc_init_data":"abc+/="}'
  MEASURE_OVMF="$tmp_dir/fixture-ovmf.fd"
  MEASURE_KERNEL="$tmp_dir/fixture-vmlinuz"
  MEASURE_INITRD="$tmp_dir/fixture-initrd.img"
)

# ── 1. render produces a self-contained package, offline ────────────────────
pkg="$tmp_dir/a/pkg"
env "${common_env[@]}" DIST_DIR="$pkg" REMOTE_HOST=invalid.invalid "$BUILD" render >/dev/null

for f in config/kata-config.toml config/containerd-runtime-handler.toml \
         k8s/runtimeclass.yaml k8s/test-pod.yaml manifest.env SHA256SUMS \
         install.sh render.py measure.py cmdline.txt README.md; do
  if [[ -f "$pkg/$f" ]]; then
    echo "ok   render: produced $f"
  else
    echo "FAIL render: missing $f" >&2
    failures=$((failures + 1))
  fi
done
check "render: never contacted a host" "absent" \
  "$([[ -e "$tmp_dir/fakebin/ssh.called" || -e "$tmp_dir/fakebin/scp.called" ]] && echo called || echo absent)"
check "render: no guest assets are copied" "" "$(find "$pkg" -type f \( -name '*.img' -o -name '*.fd' -o -name '*.container' \) -print)"

# ── 2. Kata config rewrite ─────────────────────────────────────────────────
kata="$(cat "$pkg/config/kata-config.toml")"
check_contains "kata: the image line is commented out" '# image = "/usr/share/kata-containers/kata-containers.img"' "$kata"
check_absent "kata: no active image remains" $'\nimage = ' "$kata"
check_contains "kata: kernel points at the bundle" "kernel = \"$bundle/vmlinuz\"" "$kata"
check_contains "kata: initrd points at the bundle" "initrd = \"$bundle/initramfs.img\"" "$kata"
check_contains "kata: firmware points at the bundle" "firmware = \"$bundle/OVMF.fd\"" "$kata"
check_contains "kata: rdinit is first and the stale init= is gone" \
  'kernel_params = "rdinit=/usr/local/bin/taa-init console=ttyS0 quiet"' "$kata"
check "kata: rdinit appears exactly once" "1" "$(grep -c 'rdinit=/usr/local/bin/taa-init' "$pkg/config/kata-config.toml")"
check_contains "kata: other sections are untouched" 'kernel_params = "must not be touched"' "$kata"
check_contains "kata: other keys in the section survive" 'burst = 10' "$kata"

# The renderer refuses to publish a config that would boot the wrong initrd:
# an active `image` in the target section wins over the initrd in Kata.
python3 "$RENDER" kata-config --template "$template" --section hypervisor.qemu \
  --bundle-dir "$bundle" --out "$tmp_dir/kata-ok.toml" >/dev/null
echo "ok   kata: renderer validates its own output"
sed '/^\[hypervisor.qemu\]/a image = "/wrong.img"' "$tmp_dir/kata-ok.toml" > "$tmp_dir/kata-bad.toml"
if python3 - "$RENDER" "$tmp_dir/kata-bad.toml" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("render", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    module.validate_kata_config(sys.argv[2], "hypervisor.qemu")
except SystemExit:
    sys.exit(0)
sys.exit(1)
PY
then
  echo "ok   kata: an active image is rejected"
else
  echo "FAIL kata: a config with an active image should be rejected" >&2
  failures=$((failures + 1))
fi

# ── 3. containerd merge/strip ──────────────────────────────────────────────
cat > "$tmp_dir/containerd.toml" <<'TOML'
version = 2

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."kata-qemu-csv2"]
  runtime_type = "io.containerd.kata-qemu-csv2.v2"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."kata-qemu-csv2".options]
  ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml"
TOML
cp "$tmp_dir/containerd.toml" "$tmp_dir/containerd.original.toml"

cp "$tmp_dir/containerd.toml" "$tmp_dir/merged.toml"
python3 "$RENDER" containerd-merge --config "$tmp_dir/merged.toml" \
  --handler kata-qemu-csv2-taa --runtime-type io.containerd.kata-qemu-csv2.v2 \
  --runtime-path /opt/kata/bin/containerd-shim-kata-v2 --snapshotter nydus \
  --kata-config /etc/kata-containers/configuration-qemu-csv2-taa.toml
merged="$(cat "$tmp_dir/merged.toml")"
check_contains "merge: handler table" '[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."kata-qemu-csv2-taa"]' "$merged"
check_contains "merge: options table" '[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."kata-qemu-csv2-taa".options]' "$merged"
check_contains "merge: ConfigPath" 'ConfigPath = "/etc/kata-containers/configuration-qemu-csv2-taa.toml"' "$merged"
check_contains "merge: keeps the shipped handler" 'runtimes."kata-qemu-csv2"]' "$merged"

cp "$tmp_dir/merged.toml" "$tmp_dir/merged.once.toml"
python3 "$RENDER" containerd-merge --config "$tmp_dir/merged.toml" \
  --handler kata-qemu-csv2-taa --runtime-type io.containerd.kata-qemu-csv2.v2 \
  --runtime-path /opt/kata/bin/containerd-shim-kata-v2 --snapshotter nydus \
  --kata-config /etc/kata-containers/configuration-qemu-csv2-taa.toml
if cmp -s "$tmp_dir/merged.once.toml" "$tmp_dir/merged.toml"; then
  echo "ok   merge: a second run is byte-for-byte identical"
else
  echo "FAIL merge: a second run changed the file" >&2
  failures=$((failures + 1))
fi

# The renderer's strip and the driver's inline stripper are two
# implementations; removing what merge added must restore the fixture exactly.
cp "$tmp_dir/merged.toml" "$tmp_dir/restored.toml"
python3 "$RENDER" containerd-strip --config "$tmp_dir/restored.toml" --handler kata-qemu-csv2-taa
if cmp -s "$tmp_dir/containerd.original.toml" "$tmp_dir/restored.toml"; then
  echo "ok   merge then render.py strip restores the fixture"
else
  echo "FAIL merge then render.py strip changed the fixture" >&2
  diff -u "$tmp_dir/containerd.original.toml" "$tmp_dir/restored.toml" >&2 || true
  failures=$((failures + 1))
fi

block="$(sed -n '/# BEGIN containerd-handler-strip/,/# END containerd-handler-strip/p' "$DRIVER")"
stripper="$tmp_dir/driver-strip.py"
printf '%s\n' "$block" | sed -n "/<<'PY'/,/^PY\$/p" | sed '1d;$d' > "$stripper"
if [[ -s "$stripper" ]]; then
  cp "$tmp_dir/merged.toml" "$tmp_dir/driver-restored.toml"
  python3 "$stripper" "$tmp_dir/driver-restored.toml" kata-qemu-csv2-taa
  if cmp -s "$tmp_dir/containerd.original.toml" "$tmp_dir/driver-restored.toml"; then
    echo "ok   merge then delete's inline stripper restores the fixture"
  else
    echo "FAIL merge then delete's inline stripper changed the fixture" >&2
    diff -u "$tmp_dir/containerd.original.toml" "$tmp_dir/driver-restored.toml" >&2 || true
    failures=$((failures + 1))
  fi
else
  echo "FAIL could not extract delete's inline stripper from $DRIVER" >&2
  failures=$((failures + 1))
fi

# ── 4. Kubernetes manifests ────────────────────────────────────────────────
python3 - "$pkg/k8s/runtimeclass.yaml" "$pkg/k8s/test-pod.yaml" <<'PY'
import json, sys
rc = json.load(open(sys.argv[1]))
pod = json.load(open(sys.argv[2]))
problems = []
if rc.get("kind") != "RuntimeClass" or rc.get("handler") != "kata-qemu-csv2-taa":
    problems.append(f"runtimeclass: {rc}")
spec = pod.get("spec", {})
if spec.get("runtimeClassName") != "kata-qemu-csv2-taa":
    problems.append(f"runtimeClassName: {spec.get('runtimeClassName')}")
if spec.get("nodeName") != "fixture-node":
    problems.append(f"nodeName: {spec.get('nodeName')}")
container = spec.get("containers", [{}])[0]
if container.get("image") != "172.16.10.178:31313/taa-env:slim-v2-20260916":
    problems.append(f"image: {container.get('image')}")
annotations = pod.get("metadata", {}).get("annotations", {})
if annotations.get("io.katacontainers.config.hypervisor.cc_init_data") != "abc+/=":
    problems.append(f"annotations: {annotations}")
if problems:
    print("\n".join(problems), file=sys.stderr)
    sys.exit(1)
PY
echo "ok   k8s: manifests carry the handler, node, image and annotations"

pkg2="$tmp_dir/a/pkg2"
env "${common_env[@]}" TEST_NODE_NAME="" TEST_POD_ANNOTATIONS="{}" \
  DIST_DIR="$pkg2" REMOTE_HOST=invalid.invalid "$BUILD" render >/dev/null
python3 - "$pkg2/k8s/test-pod.yaml" <<'PY'
import json, sys
pod = json.load(open(sys.argv[1]))
spec = pod["spec"]
assert "nodeName" not in spec, "nodeName should be omitted when unknown"
assert "annotations" not in pod["metadata"], "annotations should be omitted when empty"
PY
echo "ok   k8s: unknown node and empty annotations are omitted"

# ── 5. manifest and checksums ──────────────────────────────────────────────
manifest="$(cat "$pkg/manifest.env")"
check_contains "manifest: records the runtime handler" 'RUNTIME_HANDLER=kata-qemu-csv2-taa' "$manifest"
check_contains "manifest: records the bundle directory" "REMOTE_BUNDLE_DIR=$bundle" "$manifest"
check_contains "manifest: records the template source" \
  'KATA_CONFIG_TEMPLATE_SRC=/opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml' "$manifest"
check_contains "manifest: records the measurement cmdline" \
  'KERNEL_PARAMS=rdinit=/usr/local/bin/taa-init\ console=ttyS0\ quiet' "$manifest"
check "manifest: template sha is recorded" "1" \
  "$(sed -n 's/^KATA_CONFIG_TEMPLATE_SHA256=//p' "$pkg/manifest.env" | tr -d "'" | grep -cE '^[0-9a-f]{64}$')"

# ── 5b. expected MEASUREMENT ───────────────────────────────────────────────
MEASURE="$SCRIPT_DIR/render/measure.py"
expected_cmdline='tsc=reliable no_timer_check rcupdate.rcu_expedited=1 i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 noreplace-smp reboot=k cryptomgr.notests net.ifnames=0 pci=lastbus=0 console=hvc0 console=hvc1 debug panic=1 nr_cpus=3 selinux=0 scsi_mod.scan=none agent.log=debug agent.debug_console agent.debug_console_vport=1026 rdinit=/usr/local/bin/taa-init console=ttyS0 quiet'
check "measure: cmdline follows the rendered config" "$expected_cmdline" "$(cat "$pkg/cmdline.txt")"
check_contains "manifest: measurement status is computed" 'MEASUREMENT_STATUS=computed' "$manifest"
check_contains "manifest: records the SMP" 'MEASUREMENT_SMP=3' "$manifest"
check "manifest: records a 64-hex MEASUREMENT" "1" \
  "$(sed -n 's/^MEASUREMENT_HEX=//p' "$pkg/manifest.env" | tr -d "'" | grep -cE '^[0-9a-f]{64}$')"

measure_hex="$(sed -n 's/^MEASUREMENT_HEX=//p' "$pkg/manifest.env" | tr -d "'")"
direct_hex="$(python3 "$MEASURE" digest \
  --ovmf "$tmp_dir/fixture-ovmf.fd" \
  --kernel "$tmp_dir/fixture-vmlinuz" \
  --initrd "$tmp_dir/fixture-initrd.img" \
  --cmdline "$pkg/cmdline.txt" | sed -n 's/^hex=//p')"
check "measure: manifest value matches a direct recompute" "$measure_hex" "$direct_hex"
check_contains "README: shows the expected hex" "$measure_hex" "$(cat "$pkg/README.md")"
check_contains "README: points at cmdline.txt" 'cmdline.txt' "$(cat "$pkg/README.md")"

# The pure-Python SM3 must agree with an independent implementation when one
# is available (OpenSSL 3 ships sm3).
if python3 - "$MEASURE" <<'PY'
import hashlib, importlib.util, os, sys
if "sm3" not in hashlib.algorithms_available:
    print("no hashlib sm3; skipped")
    sys.exit(0)
spec = importlib.util.spec_from_file_location("measure", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for payload in (b"", b"abc", b"a" * 64, os.urandom(4097)):
    sm3 = module.SM3()
    for offset in range(0, len(payload), 37):
        sm3.update(payload[offset:offset + 37])
    assert sm3.digest() == hashlib.new("sm3", payload).digest()
PY
then
  echo "ok   measure: SM3 matches hashlib (or hashlib has no sm3)"
else
  echo "FAIL measure: SM3 disagrees with hashlib" >&2
  failures=$((failures + 1))
fi

# Recorded vector from the base initrd control cell (2026-10-10): with the
# unmodified base initrd and the debug-off cmdline, the computed value matched
# the guest report exactly. Only run when those base assets are present.
base_ovmf="$SCRIPT_DIR/base/OVMFCSV.fd"
base_kernel="$SCRIPT_DIR/base/vmlinuz-confidential-csv.container"
base_initrd="$SCRIPT_DIR/base/kata-containers-initrd-confidential-csv.img"
if [[ -f "$base_ovmf" && -f "$base_kernel" && -f "$base_initrd" ]] &&
  [[ "$(sha256sum "$base_ovmf" | awk '{print $1}')" == 508b8679be680fbc4462145870175f8624f05a9177f09239e34d557a5229fe79 ]] &&
  [[ "$(sha256sum "$base_kernel" | awk '{print $1}')" == cc7e8e9f3acd8fae7dadcff7184e5584f1304e2a95e2ea6915b3be3b3499084d ]] &&
  [[ "$(sha256sum "$base_initrd" | awk '{print $1}')" == a19d387cfd1822d8aedcd47f443fc691d6460adabdabcf46cfbe6e28ec842287 ]]; then
  cat > "$tmp_dir/historical-cmdline.txt" <<'EOF'
tsc=reliable no_timer_check rcupdate.rcu_expedited=1 i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 noreplace-smp reboot=k cryptomgr.notests net.ifnames=0 pci=lastbus=0 console=hvc0 console=hvc1 quiet panic=1 nr_cpus=1 selinux=0 scsi_mod.scan=none rdinit=/usr/local/bin/taa-init cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1
EOF
  check "measure: reproduces the recorded base-cell vector" \
    "hex=b8ad1d1168b5e1367c3acebc39adfdd4b8559a8845db6e9818c9c2f2d54a8d26" \
    "$(python3 "$MEASURE" digest --ovmf "$base_ovmf" --kernel "$base_kernel" \
      --initrd "$base_initrd" --cmdline "$tmp_dir/historical-cmdline.txt" | grep '^hex=')"
else
  echo "skip measure: recorded base vector (base assets absent or replaced)"
fi

# Without the three local input files the package must say so instead of
# publishing a made-up value.
pkg_missing="$tmp_dir/missing/pkg"
env "${common_env[@]}" MEASURE_INITRD="$tmp_dir/absent.initrd" \
  DIST_DIR="$pkg_missing" REMOTE_HOST=invalid.invalid "$BUILD" render >/dev/null
check_contains "manifest: missing inputs mark the measurement unavailable" \
  'MEASUREMENT_STATUS=unavailable' "$(cat "$pkg_missing/manifest.env")"
check "package: no cmdline.txt without measurement inputs" "absent" \
  "$([[ -e "$pkg_missing/cmdline.txt" ]] && echo present || echo absent)"
check_contains "README: explains why the measurement is missing" \
  '本包未计算预期值' "$(cat "$pkg_missing/README.md")"
if (cd "$pkg_missing" && sha256sum -c --quiet SHA256SUMS) >/dev/null 2>&1; then
  echo "ok   missing-input package still verifies"
else
  echo "FAIL missing-input package does not verify" >&2
  failures=$((failures + 1))
fi

if (cd "$pkg" && sha256sum -c --quiet SHA256SUMS) >/dev/null 2>&1; then
  echo "ok   SHA256SUMS verifies from inside the package"
else
  echo "FAIL SHA256SUMS does not verify" >&2
  failures=$((failures + 1))
fi

# ── 6. determinism ─────────────────────────────────────────────────────────
pkg_a="$tmp_dir/det-a/pkg"
pkg_b="$tmp_dir/det-b/pkg"
env "${common_env[@]}" DIST_DIR="$pkg_a" REMOTE_HOST=invalid.invalid "$BUILD" render >/dev/null
env "${common_env[@]}" DIST_DIR="$pkg_b" REMOTE_HOST=invalid.invalid "$BUILD" render >/dev/null
if diff -r "$pkg_a" "$pkg_b" >/dev/null 2>&1; then
  echo "ok   render: two runs produce identical packages"
else
  echo "FAIL render: two runs differ" >&2
  diff -r "$pkg_a" "$pkg_b" >&2 || true
  failures=$((failures + 1))
fi

# ── 7. installer is valid and self-describing ──────────────────────────────
if bash -n "$pkg/install.sh"; then
  echo "ok   install.sh: passes bash -n"
else
  echo "FAIL install.sh: syntax error" >&2
  failures=$((failures + 1))
fi
if bash "$pkg/install.sh" --help >/dev/null 2>&1; then
  echo "ok   install.sh: --help exits 0"
else
  echo "FAIL install.sh: --help failed" >&2
  failures=$((failures + 1))
fi
check_contains "install.sh: guards the template sha" 'Kata 配置模板与本包不一致' "$(cat "$pkg/install.sh")"
check_contains "install.sh: guards the base initrd sha" 'base initrd 与构建时不一致' "$(cat "$pkg/install.sh")"
check_contains "install.sh: guards every bundle digest" '与本包记录的摘要不一致' "$(cat "$pkg/install.sh")"
check_contains "install.sh: recomputes MEASUREMENT from the running QEMU" \
  '/proc/$qpid/cmdline' "$(cat "$pkg/install.sh")"
check_contains "install.sh: compares against the package value" '与包内预期一致' "$(cat "$pkg/install.sh")"
check_contains "install.sh: verifies the package first" 'sha256sum -c --quiet SHA256SUMS' "$(cat "$pkg/install.sh")"
check_contains "install.sh: supports dry-run" '--dry-run' "$(cat "$pkg/install.sh")"

# ── 8. the driver dispatches render without a preflight ────────────────────
drv_pkg="$tmp_dir/drv/pkg"
env "${common_env[@]}" DIST_DIR="$drv_pkg" REMOTE_HOST=invalid.invalid \
  "$DRIVER" render >/dev/null
if [[ -f "$drv_pkg/manifest.env" && -f "$drv_pkg/config/kata-config.toml" ]]; then
  echo "ok   driver: render reaches the renderer without a host preflight"
else
  echo "FAIL driver: render did not produce a package" >&2
  failures=$((failures + 1))
fi

# ── 9. missing template is a clear error, not a remote fetch ───────────────
out="$(env "${common_env[@]}" KATA_CONFIG_TEMPLATE="$tmp_dir/absent.toml" \
  DIST_DIR="$tmp_dir/absent-pkg" REMOTE_HOST=invalid.invalid "$BUILD" render 2>&1 || true)"
check_contains "render: missing template points at fetch-base" "fetch-base" "$out"
check "render: missing template never creates the package" "absent" \
  "$([[ -e "$tmp_dir/absent-pkg" ]] && echo present || echo absent)"

echo
if [[ "$failures" -eq 0 ]]; then
  echo "all checks passed"
else
  echo "$failures check(s) failed" >&2
  exit 1
fi
