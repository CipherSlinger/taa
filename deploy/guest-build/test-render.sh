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

# A host script ships no separate Python file: its logic is a heredoc block. Cut
# that block out so a test can run exactly what the script runs on the host.
extract_py() {
  sed -n "/^cat > \"\$\(taa_py\|tmp_pod_name\)\" <<'TAA_PY'$/,/^TAA_PY$/p" "$1" |
    sed '1d;$d' > "$2"
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

# Small guest assets; the real digest vectors are checked separately against the
# base assets when they are present. The package ships these three, so they are
# supplied through the same variables the build uses.
printf 'fixture-ovmf\n' > "$tmp_dir/fixture-ovmf.fd"
printf 'fixture-kernel\n' > "$tmp_dir/fixture-vmlinuz"
printf 'fixture-initrd\n' > "$tmp_dir/fixture-initrd.img"

# Where the package will live on the host. The rendered Kata config names this
# location, so it is pinned here and checked against the package's own bundle/.
package_host_dir="/root/taa-images/package-train"
bundle="$package_host_dir/bundle"
common_env=(
  KATA_CONFIG_TEMPLATE="$template"
  REMOTE_PACKAGE_DIR="$package_host_dir"
  REMOTE_KATA_CONFIG_SRC=/opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml
  RUNTIME_HANDLER=kata-qemu-nondcu-csv2-taa-train
  TEST_POD_NAME=test-kata-csv2-taa
  TEST_NODE_NAME=fixture-node
  TEST_POD_ANNOTATIONS='{"io.katacontainers.config.hypervisor.cc_init_data":"abc+/="}'
  INITRD_OUT="$tmp_dir/fixture-initrd.img"
  ALLOW_MISSING_TAA_ENV=1
  MEASURE_OVMF="$tmp_dir/fixture-ovmf.fd"
  MEASURE_KERNEL="$tmp_dir/fixture-vmlinuz"
  # Pin the whole deployment identity: it is rendered into kernel_params, and
  # an inherited value from the caller's shell would change every expectation
  # below. The key file points at nothing so only this variable can supply it.
  TAA_PLATFORM_KEY_FILE="$tmp_dir/absent-platform-key.json"
  TAA_PLATFORM_IP=172.16.10.116:18080
  TAA_DOCKER_ID=fixture-docker-id
  PLATFORM_PUBLIC_KEY="04$(printf 'a%.0s' {1..128})"
  TAA_PLATFORM_SM2_ID=fixture-sm2-id
  TAA_CONTRACT_ID=fixture-contract-id
  # The role owns CONTRACT_TYPE, so the fixture pins the role instead: a value
  # here would be reported and discarded, and the rendered token would not be
  # what this line says.
  TAA_ROLE=taa-train
  TAA_LLM_ENDPOINT=https://172.16.10.116:8443
  TAA_ADDR=0.0.0.0:6001
)

# The identity tokens render_package writes into the test Pod's kernel_params
# annotation, in emission order. Kept in one place so the Pod and cmdline
# expectations cannot drift.
identity_params="taa.platform_ip=172.16.10.116:18080 taa.docker_id=fixture-docker-id taa.platform_public_key=04$(printf 'a%.0s' {1..128}) taa.platform_sm2_id=fixture-sm2-id taa.contract_id=fixture-contract-id taa.contract_type=1 taa.taa_llm_endpoint=https://172.16.10.116:8443 taa.taa_addr=0.0.0.0:6001"

# ── 1. render produces a self-contained package, offline ────────────────────
pkg="$tmp_dir/a/pkg"
env "${common_env[@]}" DIST_DIR="$pkg" REMOTE_HOST=invalid.invalid "$BUILD" render >/dev/null

for f in kata-config.toml config/containerd-runtime-handler.toml \
         k8s/runtimeclass.yaml test/test-pod.yaml \
         test/create-test-pod.sh test/delete-test-pod.sh SHA256SUMS \
         install.sh uninstall.sh README.md \
         bundle/initramfs.img bundle/vmlinuz bundle/OVMF.fd; do
  if [[ -f "$pkg/$f" ]]; then
    echo "ok   render: produced $f"
  else
    echo "FAIL render: missing $f" >&2
    failures=$((failures + 1))
  fi
done
check "render: ships no separate renderer" "absent" \
  "$([[ -e "$pkg/render.py" ]] && echo present || echo absent)"
check "render: ships no separate measurement script" "absent" \
  "$([[ -e "$pkg/measure.py" ]] && echo present || echo absent)"
check "render: never contacted a host" "absent" \
  "$([[ -e "$tmp_dir/fakebin/ssh.called" || -e "$tmp_dir/fakebin/scp.called" ]] && echo called || echo absent)"
check "render: ships no per-package drop-in (it is shared beside the packages)" "absent" \
  "$([[ -e "$pkg/config/zz-taa-runtimes.toml" ]] && echo present || echo absent)"
# The package is the runtime dependency: it carries the exact files QEMU boots,
# so deploying on another host needs nothing from that host's Kata tree.
check "bundle: ships the built initrd" "fixture-initrd" "$(cat "$pkg/bundle/initramfs.img")"
check "bundle: ships the kernel" "fixture-kernel" "$(cat "$pkg/bundle/vmlinuz")"
check "bundle: ships OVMF" "fixture-ovmf" "$(cat "$pkg/bundle/OVMF.fd")"

# ── 2. Kata config rewrite ─────────────────────────────────────────────────
kata="$(cat "$pkg/kata-config.toml")"
check_contains "kata: the image line is commented out" '# image = "/usr/share/kata-containers/kata-containers.img"' "$kata"
check_absent "kata: no active image remains" $'\nimage = ' "$kata"
check_contains "kata: kernel points at the bundle" "kernel = \"$bundle/vmlinuz\"" "$kata"
check_contains "kata: initrd points at the bundle" "initrd = \"$bundle/initramfs.img\"" "$kata"
check_contains "kata: firmware points at the bundle" "firmware = \"$bundle/OVMF.fd\"" "$kata"
check_contains "kata: rdinit is first and stale init= is gone" \
  "kernel_params = \"rdinit=/usr/local/bin/taa-init console=ttyS0 quiet\"" "$kata"
check "kata: rdinit appears exactly once" "1" "$(grep -c 'rdinit=/usr/local/bin/taa-init' "$pkg/kata-config.toml")"
check_contains "kata: other sections are untouched" 'kernel_params = "must not be touched"' "$kata"
check_contains "kata: other keys in the section survive" 'burst = 10' "$kata"

# Rendering an already-rendered config is the realistic way to duplicate tokens.
# --param replaces a token with the same key instead of appending a second one,
# so a re-render cannot leave two values for the guest to choose between.
python3 "$RENDER" kata-config --template "$pkg/kata-config.toml" \
  --section hypervisor.qemu --bundle-dir "$bundle" \
  --param taa.platform_ip=10.0.0.1 --param taa.taa_addr=0.0.0.0:6001 \
  --out "$tmp_dir/kata-again.toml" >/dev/null
python3 "$RENDER" kata-config --template "$tmp_dir/kata-again.toml" \
  --section hypervisor.qemu --bundle-dir "$bundle" \
  --param taa.platform_ip=10.0.0.2 --param taa.taa_addr=0.0.0.0:6001 \
  --out "$tmp_dir/kata-again2.toml" >/dev/null
again="$(cat "$tmp_dir/kata-again2.toml")"
check "kata: a re-render never duplicates a key" "" \
  "$(grep -o 'taa\.[a-z0-9_]*=' "$tmp_dir/kata-again2.toml" | sort | uniq -d)"
check "kata: a re-render keeps every extra key" "2" \
  "$(grep -o 'taa\.[a-z0-9_]*=' "$tmp_dir/kata-again2.toml" | sort -u | wc -l)"
check "kata: a re-render does not stack tokens" "1" \
  "$(grep -o 'taa\.platform_ip=' "$tmp_dir/kata-again2.toml" | wc -l)"
check_contains "kata: a re-render carries the new value" 'taa.platform_ip=10.0.0.2' "$again"
check_absent "kata: a re-render drops the old value" 'taa.platform_ip=10.0.0.1' "$again"

# default_memory is a runtime dependency, not a tuning knob: a CSV2 guest sizes
# its writable root at about half of it and the CDH unpacks the image there. The
# override has to replace the template's value (never add a second key) and has
# to appear even when the template has none.
python3 "$RENDER" kata-config --template "$pkg/kata-config.toml" \
  --section hypervisor.qemu --bundle-dir "$bundle" \
  --memory-mib 23552 --out "$tmp_dir/kata-mem.toml" >/dev/null
check "memory: the override replaces the template value" "23552" \
  "$(sed -n 's/^default_memory = //p' "$tmp_dir/kata-mem.toml")"
check "memory: exactly one key survives" "1" \
  "$(grep -c '^default_memory = ' "$tmp_dir/kata-mem.toml")"

sed 's/^default_memory = .*/# default_memory removed/' "$pkg/kata-config.toml" > "$tmp_dir/kata-no-mem.toml"
python3 "$RENDER" kata-config --template "$tmp_dir/kata-no-mem.toml" \
  --section hypervisor.qemu --bundle-dir "$bundle" \
  --memory-mib 23552 --out "$tmp_dir/kata-mem-added.toml" >/dev/null
check "memory: a template without the key still gets the override" "23552" \
  "$(sed -n 's/^default_memory = //p' "$tmp_dir/kata-mem-added.toml")"

# ── 2b. the deployment identity rides the Pod, not the runtime config ──────
# Kata appends a Pod's kernel_params annotation to the runtime config's own
# parameters, so the identity belongs to the Pod that runs and the installed
# config stays identity-free. What matters here is that the package's test Pod
# carries exactly the tokens the build rendered, that a consumer-supplied
# annotation is appended in Kata's order, and that a malformed token is refused
# instead of silently splitting the command line.
pod_file="$pkg/test/test-pod.yaml"
check "identity: the Kata config carries no taa.* token" "0" \
  "$(grep -o 'taa\.[a-z0-9_]*=' "$pkg/kata-config.toml" | wc -l)"
check "identity: the test Pod carries exactly the eight tokens" "$identity_params" \
  "$(python3 "$RENDER" pod-kernel-params --pod "$pod_file")"

# A Pod may already carry kernel_params of its own (the CDH timeouts, for
# example); the identity is appended, not substituted.
python3 "$RENDER" k8s --handler fixture-handler --pod fixture-pod \
  --image example.invalid/image:tag \
  --annotations '{"io.katacontainers.config.hypervisor.kernel_params":"agent.cdh_api_timeout=1200"}' \
  --kernel-param taa.docker_id=fixture-docker-id \
  --out-dir "$tmp_dir/k8s-merge" --pod-dir "$tmp_dir/k8s-merge" >/dev/null
check "identity: the annotation is appended to an existing kernel_params" \
  "agent.cdh_api_timeout=1200 taa.docker_id=fixture-docker-id" \
  "$(python3 "$RENDER" pod-kernel-params --pod "$tmp_dir/k8s-merge/test-pod.yaml")"

# The recovery key is a deployment identity too: its token is the environment
# variable in lower case and must reach the annotation.
secret_ident="$tmp_dir/k8s-secret"
python3 "$RENDER" k8s --handler fixture-handler --pod fixture-pod \
  --image example.invalid/image:tag \
  --kernel-param "taa.taasecretkey=$(printf 'ab%.0s' {1..60})" \
  --out-dir "$secret_ident" --pod-dir "$secret_ident" >/dev/null
check_contains "identity: the recovery key rides the annotation" \
  'taa.taasecretkey=' "$(python3 "$RENDER" pod-kernel-params --pod "$secret_ident/test-pod.yaml")"

# A whitespace-bearing value would become two kernel parameters, so the
# renderer refuses it rather than letting the guest apply half a token.
out="$(python3 "$RENDER" k8s --handler fixture-handler --pod fixture-pod \
  --image example.invalid/image:tag \
  --kernel-param 'taa.docker_id=two words' \
  --out-dir "$tmp_dir/k8s-bad" --pod-dir "$tmp_dir/k8s-bad" 2>&1 || true)"
check_contains "identity: a whitespace-bearing token is refused" \
  'one non-empty token' "$out"
check "  (nothing rendered)" "absent" \
  "$([[ -e "$tmp_dir/k8s-bad/test-pod.yaml" ]] && echo present || echo absent)"

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

# ── 3. the Pod image archive ───────────────────────────────────────────────
# A CoCo guest pulls the image through CDH from the registry the Pod names, so
# the host's docker daemon is not in that path. The package therefore ships the
# archive and install.sh pushes it when the registry lacks the tag. What has to
# hold here: the archive lands under a name derived from the image reference,
# keeps its own suffix, is covered by SHA256SUMS, and package-info reports it.
image_archive="$tmp_dir/test-image.tar.gz"
printf 'not a real image\n' > "$image_archive"
image_pkg="$tmp_dir/image-pkg"
# package-info resolves the handler's ConfigPath back to this directory, so the
# package has to be rendered for the location it ends up in. The other render
# tests deliberately render for a remote path; these two need a self-consistent
# package to ask package-info about.
env "${common_env[@]}" DIST_DIR="$image_pkg" REMOTE_HOST=invalid.invalid \
  REMOTE_PACKAGE_DIR="$image_pkg" REMOTE_BUNDLE_DIR="$image_pkg/bundle" \
  REMOTE_KATA_CONFIG="$image_pkg/kata-config.toml" \
  TEST_IMAGE=172.16.10.178:31313/taa-env:fixture-tag \
  TEST_IMAGE_ARCHIVE="$image_archive" "$BUILD" render >/dev/null

image_name="taa-env_fixture-tag.tar.gz"
check "image: the archive name drops the registry prefix" "present" \
  "$([[ -f "$image_pkg/image/$image_name" ]] && echo present || echo absent)"
check "image: the packaged bytes are the archive's" "same" \
  "$(cmp -s "$image_archive" "$image_pkg/image/$image_name" && echo same || echo different)"
check "image: SHA256SUMS covers the archive" "1" \
  "$(cd "$image_pkg" && grep -c "image/$image_name" SHA256SUMS)"
check "image: package-info reports the archive" "image/$image_name" \
  "$(python3 "$RENDER" package-info --dir "$image_pkg" | sed -n 's/^TEST_IMAGE_ARCHIVE=//p' | tr -d "'")"
check "image: package-info reports the image reference" "172.16.10.178:31313/taa-env:fixture-tag" \
  "$(python3 "$RENDER" package-info --dir "$image_pkg" | sed -n 's/^TEST_IMAGE=//p' | tr -d "'")"

# Without an archive the package is still installable; install.sh then requires
# the registry to hold the image already. Empty means exactly that, not "broken".
noimg_pkg="$tmp_dir/noimg-pkg"
env "${common_env[@]}" DIST_DIR="$noimg_pkg" REMOTE_HOST=invalid.invalid \
  REMOTE_PACKAGE_DIR="$noimg_pkg" REMOTE_BUNDLE_DIR="$noimg_pkg/bundle" \
  REMOTE_KATA_CONFIG="$noimg_pkg/kata-config.toml" \
  "$BUILD" render >/dev/null
check "image: no archive means no image/ directory" "absent" \
  "$([[ -d "$noimg_pkg/image" ]] && echo present || echo absent)"
check "image: no archive reports empty" "" \
  "$(python3 "$RENDER" package-info --dir "$noimg_pkg" | sed -n 's/^TEST_IMAGE_ARCHIVE=//p' | tr -d "'")"

# A missing archive is a render error, not a package that silently expects the
# image to be somewhere else.
missing_pkg="$tmp_dir/missing-pkg"
missing_out="$(env "${common_env[@]}" DIST_DIR="$missing_pkg" REMOTE_HOST=invalid.invalid \
  TEST_IMAGE_ARCHIVE="$tmp_dir/definitely-not-here.tar" "$BUILD" render 2>&1 || true)"
check_contains "image: a missing archive fails the render" "TEST_IMAGE_ARCHIVE does not exist" "$missing_out"
check "image: a failed render never creates the package" "absent" \
  "$([[ -d "$missing_pkg" ]] && echo present || echo absent)"

# A plain .tar keeps its own suffix; the name is not allowed to claim gzip.
check "image: a .tar archive keeps .tar" "taa-env_fixture-tag.tar" \
  "$(python3 "$RENDER" image-archive-name --image 172.16.10.178:31313/taa-env:fixture-tag \
      --like "$tmp_dir/plain.tar")"

# ── 4. containerd merge/strip ──────────────────────────────────────────────
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
  --handler kata-qemu-nondcu-csv2-taa-train --runtime-type io.containerd.kata-qemu-csv2.v2 \
  --runtime-path /opt/kata/bin/containerd-shim-kata-v2 --snapshotter nydus \
  --kata-config /etc/kata-containers/configuration-qemu-csv2-taa.toml
merged="$(cat "$tmp_dir/merged.toml")"
check_contains "merge: handler table" '[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."kata-qemu-nondcu-csv2-taa-train"]' "$merged"
check_contains "merge: options table" '[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."kata-qemu-nondcu-csv2-taa-train".options]' "$merged"
check_contains "merge: ConfigPath" 'ConfigPath = "/etc/kata-containers/configuration-qemu-csv2-taa.toml"' "$merged"
check_contains "merge: keeps the shipped handler" 'runtimes."kata-qemu-csv2"]' "$merged"

cp "$tmp_dir/merged.toml" "$tmp_dir/merged.once.toml"
python3 "$RENDER" containerd-merge --config "$tmp_dir/merged.toml" \
  --handler kata-qemu-nondcu-csv2-taa-train --runtime-type io.containerd.kata-qemu-csv2.v2 \
  --runtime-path /opt/kata/bin/containerd-shim-kata-v2 --snapshotter nydus \
  --kata-config /etc/kata-containers/configuration-qemu-csv2-taa.toml
if cmp -s "$tmp_dir/merged.once.toml" "$tmp_dir/merged.toml"; then
  echo "ok   merge: a second run is byte-for-byte identical"
else
  echo "FAIL merge: a second run changed the file" >&2
  failures=$((failures + 1))
fi

# Removing what merge added must restore the fixture exactly.
cp "$tmp_dir/merged.toml" "$tmp_dir/restored.toml"
python3 "$RENDER" containerd-strip --config "$tmp_dir/restored.toml" --handler kata-qemu-nondcu-csv2-taa-train
if cmp -s "$tmp_dir/containerd.original.toml" "$tmp_dir/restored.toml"; then
  echo "ok   merge then render.py strip restores the fixture"
else
  echo "FAIL merge then render.py strip changed the fixture" >&2
  diff -u "$tmp_dir/containerd.original.toml" "$tmp_dir/restored.toml" >&2 || true
  failures=$((failures + 1))
fi

# ── 4b. containerd drop-in ──────────────────────────────────────────────────
# containerd loads the main config and then its imports in order; the last file
# that defines a runtime handler replaces the whole CRI plugin tree. A drop-in
# carrying only its own handler therefore deletes every other runtime, so the
# generator has to emit a full snapshot of the host's current map.
dropin_dir="$tmp_dir/dropin"
dconf="$dropin_dir/conf.d"
mkdir -p "$dconf"
cat > "$dropin_dir/main.toml" <<EOF
version = 2
imports = ["$dconf/*.toml"]

[plugins."io.containerd.grpc.v1.cri"]
  sandbox_image = "example/pause:3.8"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.main-only]
  runtime_type = "io.containerd.runc.v2"
EOF
cat > "$dconf/99-nvidia.toml" <<'TOML'
version = 2
[plugins]
  [plugins."io.containerd.grpc.v1.cri"]
    sandbox_image = "registry.aliyuncs.com/google_containers/pause:3.9"
    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nvidia]
      runtime_type = "io.containerd.runc.v2"
    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-qemu-csv2]
      runtime_type = "io.containerd.kata-qemu-csv2.v2"
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-qemu-csv2.options]
        ConfigPath = "/etc/kata-containers/configuration-qemu-csv2.toml"
TOML
cat > "$dconf/zz-taa-runtimes.toml" <<'TOML'
version = 2
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.fixture-handler]
  runtime_type = "old"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.fixture-handler.options]
  ConfigPath = "/tmp/old-path.toml"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.other-package]
  runtime_type = "io.containerd.kata-qemu-csv2.v2"
TOML

# The derived drop-in must not become its own source, or the host's later
# changes to 99-nvidia.toml would never be picked up again.
check "dropin: skips TAA-owned files when choosing the base" "$dconf/99-nvidia.toml" \
  "$(python3 "$RENDER" containerd-effective-source --config "$dropin_dir/main.toml" \
      --exclude-prefix zz-taa)"

dropin_args=(--config "$dropin_dir/main.toml" --exclude-prefix zz-taa
  --handler fixture-handler --runtime-type io.containerd.kata-qemu-csv2.v2
  --runtime-path /opt/kata/bin/containerd-shim-kata-v2 --snapshotter nydus
  --kata-config /root/taa-images/pkg/kata-config.toml)
python3 "$RENDER" containerd-dropin "${dropin_args[@]}" \
  --carry "$dconf/zz-taa-runtimes.toml" --out "$dropin_dir/first.toml"
dropin="$(cat "$dropin_dir/first.toml")"
check_contains "dropin: keeps the host's nvidia handler" 'runtimes.nvidia]' "$dropin"
check_contains "dropin: keeps the host's kata handler" 'runtimes.kata-qemu-csv2]' "$dropin"
check_contains "dropin: carries another package's handler" 'runtimes.other-package]' "$dropin"
check_contains "dropin: keeps the host's CRI settings" \
  'sandbox_image = "registry.aliyuncs.com/google_containers/pause:3.9"' "$dropin"
check "dropin: does not snapshot the whole main config" "0" \
  "$(grep -c 'runtimes.main-only' "$dropin_dir/first.toml" || true)"
check "dropin: defines its own handler exactly once" "1" \
  "$(grep -cE 'runtimes\."?fixture-handler"?\]$' "$dropin_dir/first.toml" || true)"
check_contains "dropin: writes the new ConfigPath" \
  'ConfigPath = "/root/taa-images/pkg/kata-config.toml"' "$dropin"
check_absent "dropin: drops the stale ConfigPath" \
  'ConfigPath = "/tmp/old-path.toml"' "$dropin"
check_contains "dropin: explains why it is a snapshot" 'Seeded once from' "$dropin"

# Reinstalling is the common case: the same two files must produce the same
# bytes, which is only true if handlers already in the base are not re-appended.
python3 "$RENDER" containerd-dropin "${dropin_args[@]}" \
  --carry "$dropin_dir/first.toml" --out "$dropin_dir/second.toml"
if cmp -s "$dropin_dir/first.toml" "$dropin_dir/second.toml"; then
  echo "ok   dropin: a second run is byte-for-byte identical"
else
  echo "FAIL dropin: a second run changed the file" >&2
  diff -u "$dropin_dir/first.toml" "$dropin_dir/second.toml" >&2 || true
  failures=$((failures + 1))
fi

# A reinstall reuses the package copy as the snapshot (--base) instead of
# re-reading the host, so host edits after the first install do not silently
# rewrite the package. The generated header must not be duplicated.
python3 "$RENDER" containerd-dropin "${dropin_args[@]}" \
  --base "$dropin_dir/first.toml" --out "$dropin_dir/frombase.toml"
if cmp -s "$dropin_dir/first.toml" "$dropin_dir/frombase.toml"; then
  echo "ok   dropin: --base reuses the package copy unchanged"
else
  echo "FAIL dropin: --base changed the package copy" >&2
  diff -u "$dropin_dir/first.toml" "$dropin_dir/frombase.toml" >&2 || true
  failures=$((failures + 1))
fi
check "dropin: --base keeps one header" "1" \
  "$(grep -c 'Generated by TAA' "$dropin_dir/frombase.toml" || true)"

# Uninstall reads the installed drop-in's handler list, removes exactly one
# handler, and leaves every other handler and CRI setting in place.
handlers_out="$(python3 "$RENDER" containerd-handlers --file "$dropin_dir/first.toml")"
check_contains "handlers: lists this package's handler" 'fixture-handler' "$handlers_out"
check_contains "handlers: lists the host's handlers" 'kata-qemu-csv2' "$handlers_out"
python3 "$RENDER" containerd-remove --file "$dropin_dir/first.toml" \
  --handler fixture-handler --out "$dropin_dir/removed.toml"
removed="$(cat "$dropin_dir/removed.toml")"
check_absent "remove: drops this package's handler" 'fixture-handler' "$removed"
check_contains "remove: keeps the host's nvidia handler" 'runtimes.nvidia]' "$removed"
check_contains "remove: keeps another package's handler" 'runtimes.other-package]' "$removed"
check_contains "remove: keeps the host's CRI settings" \
  'sandbox_image = "registry.aliyuncs.com/google_containers/pause:3.9"' "$removed"
remaining_taa="$(python3 "$RENDER" containerd-handlers --file "$dropin_dir/removed.toml" |
  grep -E '^kata-qemu-(nondcu|dcu)-csv2-taa-' || true)"
check "remove: no TAA handler remains, so the drop-in is deletable" "" "$remaining_taa"

extract_py "$pkg/uninstall.sh" "$tmp_dir/uninstall-block.py"
python3 "$tmp_dir/uninstall-block.py" remove \
  --file "$dropin_dir/first.toml" --handler fixture-handler \
  --out "$dropin_dir/embedded-removed.toml"
if cmp -s "$dropin_dir/removed.toml" "$dropin_dir/embedded-removed.toml"; then
  echo "ok   uninstall block: remove matches the build-host renderer"
else
  echo "FAIL uninstall block: remove differs" >&2
  diff -u "$dropin_dir/removed.toml" "$dropin_dir/embedded-removed.toml" >&2 || true
  failures=$((failures + 1))
fi
check "uninstall block: handlers match the build-host renderer" "$handlers_out" \
  "$(python3 "$tmp_dir/uninstall-block.py" handlers "$dropin_dir/first.toml")"

# The staging config is how install.sh resolves the prospective result before
# touching /etc; the new drop-in has to be the last import so it wins.
python3 "$RENDER" containerd-stage --config "$dropin_dir/main.toml" \
  --extra "$dropin_dir/first.toml" --out "$dropin_dir/stage.toml"
stage_imports="$(grep '^imports' "$dropin_dir/stage.toml")"
check_contains "stage: keeps the expanded imports" "$dconf/99-nvidia.toml" "$stage_imports"
check_contains "stage: appends the drop-in last" "first.toml\"]" "$stage_imports"
check_absent "stage: the glob is gone" '*.toml' "$stage_imports"

# 3b. Each host script carries its own copy of the TOML handling. Run those
# copies over the same fixtures and compare bytes: a helper left out of an
# embedded block then fails here instead of on a host in the middle of install.
extract_py "$pkg/install.sh" "$tmp_dir/install-block.py"
python3 "$tmp_dir/install-block.py" dropin "${dropin_args[@]}" \
  --carry "$dconf/zz-taa-runtimes.toml" --out "$dropin_dir/embedded-first.toml"
if cmp -s "$dropin_dir/first.toml" "$dropin_dir/embedded-first.toml"; then
  echo "ok   install block: dropin matches the build-host renderer"
else
  echo "FAIL install block: dropin differs" >&2
  diff -u "$dropin_dir/first.toml" "$dropin_dir/embedded-first.toml" >&2 || true
  failures=$((failures + 1))
fi
python3 "$tmp_dir/install-block.py" stage \
  --config "$dropin_dir/main.toml" --extra "$dropin_dir/first.toml" \
  --out "$dropin_dir/embedded-stage.toml"
if cmp -s "$dropin_dir/stage.toml" "$dropin_dir/embedded-stage.toml"; then
  echo "ok   install block: stage matches the build-host renderer"
else
  echo "FAIL install block: stage differs" >&2
  diff -u "$dropin_dir/stage.toml" "$dropin_dir/embedded-stage.toml" >&2 || true
  failures=$((failures + 1))
fi

# ── 4. Kubernetes manifests ────────────────────────────────────────────────
python3 - "$pkg/k8s/runtimeclass.yaml" "$pkg/test/test-pod.yaml" <<'PY'
import json, sys
rc = json.load(open(sys.argv[1]))
pod = json.load(open(sys.argv[2]))
problems = []
if rc.get("kind") != "RuntimeClass" or rc.get("handler") != "kata-qemu-nondcu-csv2-taa-train":
    problems.append(f"runtimeclass: {rc}")
spec = pod.get("spec", {})
if spec.get("runtimeClassName") != "kata-qemu-nondcu-csv2-taa-train":
    problems.append(f"runtimeClassName: {spec.get('runtimeClassName')}")
if spec.get("nodeName") != "fixture-node":
    problems.append(f"nodeName: {spec.get('nodeName')}")
container = spec.get("containers", [{}])[0]
if container.get("image") != "172.16.10.178:31313/taa-env:v1-train-infer":
    problems.append(f"image: {container.get('image')}")
# The test Pod is only a keep-alive for the VM the boot checks inspect, so its
# command must not end on its own.
if "sleep infinity" not in " ".join(container.get("command") or []):
    problems.append(f"command: {container.get('command')}")
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
python3 - "$pkg2/test/test-pod.yaml" <<'PY'
import json, sys
pod = json.load(open(sys.argv[1]))
spec = pod["spec"]
assert "nodeName" not in spec, "nodeName should be omitted when unknown"
annotations = pod["metadata"].get("annotations", {})
assert set(annotations) == {"io.katacontainers.config.hypervisor.kernel_params"}, annotations
PY
echo "ok   k8s: unknown node is omitted; the identity annotation is the only one"

# ── 5. package self-description ────────────────────────────────────────────
# The package carries no parameter sheet and no renderer: install.sh carries a
# small reader of its own, which the block below is extracted from and run, so
# the test exercises exactly what the script does on the host.
# Render one where it will live, so the absolute paths resolve.
self_pkg="$tmp_dir/self/pkg"
env "${common_env[@]}" REMOTE_PACKAGE_DIR="$self_pkg" DIST_DIR="$self_pkg" \
  REMOTE_HOST=invalid.invalid "$BUILD" render >/dev/null
# The package ships no renderer: the host scripts carry the reading they need.
extract_py "$self_pkg/install.sh" "$tmp_dir/self-info.py"
info="$(python3 "$tmp_dir/self-info.py" info "$self_pkg")"
check_contains "package-info: reports the runtime handler" "RUNTIME_HANDLER=kata-qemu-nondcu-csv2-taa-train" "$info"
check_contains "package-info: reports the runtime type" \
  "RUNTIME_TYPE=io.containerd.kata-qemu-csv2.v2" "$info"
check_contains "package-info: reports the snapshotter" "SNAPSHOTTER=nydus" "$info"
check_contains "package-info: derives the bundle directory" "REMOTE_BUNDLE_DIR=$self_pkg/bundle" "$info"
check_contains "package-info: derives the ConfigPath" \
  "REMOTE_KATA_CONFIG=$self_pkg/kata-config.toml" "$info"
check_contains "package-info: derives the hypervisor section" \
  "KATA_HYPERVISOR_SECTION=hypervisor.qemu" "$info"
check_contains "package-info: derives the node name" "TEST_NODE_NAME=fixture-node" "$info"
check_contains "package-info: locates the RuntimeClass under k8s/" \
  "PACKAGE_RUNTIMECLASS=k8s/runtimeclass.yaml" "$info"
# The Pod name and location are read by the script that acts on the Pod, not by
# the installer, so they are asserted against create-test-pod.sh's own reader.
extract_py "$self_pkg/test/create-test-pod.sh" "$tmp_dir/self-create-info.py"
pod_info="$(python3 "$tmp_dir/self-create-info.py" info "$self_pkg")"
check_contains "package-info: derives the Pod name" "TEST_POD_NAME=test-kata-csv2-taa" "$pod_info"
check_contains "package-info: locates the test Pod under test/" \
  "PACKAGE_TEST_POD=test/test-pod.yaml" "$pod_info"

# A package moved after rendering names files that are no longer beside it. That
# is the check the manifest used to carry, now made from the package's own text.
moved_pkg="$tmp_dir/moved/pkg"
mkdir -p "$tmp_dir/moved"
mv "$self_pkg" "$moved_pkg"
out="$(python3 "$tmp_dir/self-info.py" info "$moved_pkg" 2>&1 || true)"
check_contains "package-info: refuses a moved package" "does not point at" "$out"

# ── 5a. instance role ──────────────────────────────────────────────────────
# The role decides what the host ends up holding, so what matters here is that
# the three roles cannot collide -- a shared handler, package directory or Pod
# name would let one role install over another -- and that only the training
# role asks for the semgrep payload.
role_config() {
  env "${common_env[@]}" REMOTE_HOST=invalid.invalid "$BUILD" "$1" print-config
}

check "role: the default is taa-train" "taa-train" \
  "$(env "${common_env[@]}" "$BUILD" print-config | sed -n 's/^TAA_ROLE=//p' | tr -d "'")"
check "role: train keeps CONTRACT_TYPE=1" "1" \
  "$(role_config taa-train | sed -n 's/^TAA_CONTRACT_TYPE=//p' | tr -d "'")"
check "role: infer selects CONTRACT_TYPE=2" "2" \
  "$(role_config taa-infer | sed -n 's/^TAA_CONTRACT_TYPE=//p' | tr -d "'")"
check "role: analysis selects CONTRACT_TYPE=3" "3" \
  "$(role_config taa-analysis | sed -n 's/^TAA_CONTRACT_TYPE=//p' | tr -d "'")"

# The handler, the package directory and the Pod name are the three things that
# must not be shared: the first two because containerd resolves boot assets
# through them, the last because a Pod's role cannot be changed in place.
for role in taa-train taa-infer taa-analysis taa-train-dcu taa-infer-dcu; do
  # The two DCU roles extend a different runtime class and therefore carry a
  # different handler prefix; everything else about the role naming is shared.
  case "$role" in
    taa-train-dcu) want_handler=kata-qemu-dcu-csv2-taa-train; want_pkg=package-train-dcu ;;
    taa-infer-dcu) want_handler=kata-qemu-dcu-csv2-taa-infer; want_pkg=package-infer-dcu ;;
    *) want_handler=kata-qemu-nondcu-csv2-taa-${role#taa-}; want_pkg=package-${role#taa-} ;;
  esac
  # The common fixture pins the handler, the package directory and the Pod name
  # (other sections assert against those literals), so they are blanked here:
  # an empty value is exactly what makes the role default apply.
  derived="$(env "${common_env[@]}" RUNTIME_HANDLER= REMOTE_PACKAGE_DIR= TEST_POD_NAME= \
    REMOTE_HOST=invalid.invalid "$BUILD" "$role" print-config)"
  dh="$(sed -n 's/^RUNTIME_HANDLER=//p' <<<"$derived" | tr -d "'")"
  dp="$(sed -n 's/^REMOTE_PACKAGE_DIR=//p' <<<"$derived" | tr -d "'")"
  dn="$(sed -n 's/^TEST_POD_NAME=//p' <<<"$derived" | tr -d "'")"
  # The suffix has to be the role's own, not merely present: a train package
  # installed under the infer handler would attach the wrong kernel.
  check "role/$role: handler is $role's own" "$want_handler" "$dh"
  # Same rule as the handler: the directory owns the role's suffix, so an
  # explicit override can never quietly land one role on another's package.
  check "role/$role: package dir is $want_pkg" \
    "/root/taa-images/$want_pkg" "$dp"
  case "$dn" in
    test-kata-*csv2-taa*) echo "ok   role/$role: Pod name is role-scoped ($dn)" ;;
    *) echo "FAIL role/$role: Pod name is not role-scoped: $dn" >&2; failures=$((failures + 1)) ;;
  esac
  printf '%s\n%s\n' "$dh" "$dp" >> "$tmp_dir/role-names.txt"
done
check "role: none of the roles share a handler or package directory" "0" \
  "$(sort "$tmp_dir/role-names.txt" | uniq -d | wc -l)"

# Only the training role ships the payload. The analysis role's config is
# injected with the regex engine so the guest does not log a fallback on every
# boot; infer and analysis both skip staging it.
check_contains "role: only train declares the semgrep payload" \
  'role_wants_semgrep() {' "$(cat "$BUILD")"
check_contains "role: the payload gate needs both the role and the config" \
  'role_wants_semgrep && taa_config_wants_semgrep' "$(cat "$BUILD")"

# The analysis Pod needs a numeric uid: its jupyter base names its user, and the
# guest-pull snapshotter cannot resolve a name. The other roles leave it to the
# image (which sets USER 0 for exactly this reason).
check "role: analysis pins a numeric uid for its Pod" "0" \
  "$(role_config taa-analysis | sed -n 's/^TEST_POD_RUN_AS_USER=//p' | tr -d "'")"
check "role: train leaves the uid to the image" "" \
  "$(role_config taa-train | sed -n 's/^TEST_POD_RUN_AS_USER=//p' | tr -d "'")"

# Render each role's pod: the uid has to reach the manifest, and the handler has
# to match the role's own.
analysis_pkg="$tmp_dir/role/pkg-analysis"
env "${common_env[@]}" REMOTE_HOST=invalid.invalid DIST_DIR="$analysis_pkg" \
  RUNTIME_HANDLER= TAA_CONTRACT_TYPE=3 TEST_POD_NAME=test-kata-csv2-taa-analysis \
  TEST_POD_RUN_AS_USER=0 "$BUILD" taa-analysis render >/dev/null
python3 - "$analysis_pkg/test/test-pod.yaml" <<'PY'
import json, sys
pod = json.load(open(sys.argv[1]))
c = pod["spec"]["containers"][0]
problems = []
if c.get("securityContext", {}).get("runAsUser") != 0:
    problems.append(f"runAsUser: {c.get('securityContext')}")
if problems:
    print("\n".join(problems), file=sys.stderr)
    sys.exit(1)
PY
echo "ok   role: the analysis Pod carries runAsUser=0"

# ── 5b. DCU role package ───────────────────────────────────────────────────
# A DCU package has to differ from its CPU counterpart in exactly the places
# the guest and the scheduler read: the runtime class the handler extends, the
# kernel module taa-init loads and the extended resource the test Pod requests.
# The same fixture template stands in for the DCU template here.
dcu_pkg="$tmp_dir/role/pkg-train-dcu"
env "${common_env[@]}" REMOTE_HOST=invalid.invalid DIST_DIR="$dcu_pkg" \
  RUNTIME_HANDLER= RUNTIME_TYPE= REMOTE_PACKAGE_DIR= TEST_POD_NAME= \
  TAA_MODULES= TEST_POD_DEVICE_RESOURCE= KATA_DEFAULT_MEMORY= \
  "$BUILD" taa-train-dcu render >/dev/null
dcu_identity="$(python3 "$RENDER" pod-kernel-params --pod "$dcu_pkg/test/test-pod.yaml")"
check_contains "dcu: the handler is the DCU one" \
  '"handler": "kata-qemu-dcu-csv2-taa-train"' "$(cat "$dcu_pkg/k8s/runtimeclass.yaml")"
check_contains "dcu: the runtime type extends the DCU class" \
  'runtime_type = "io.containerd.kata-qemu-hygon-dcu-csv2.v2"' \
  "$(cat "$dcu_pkg/config/containerd-runtime-handler.toml")"
check_contains "dcu: the guest is told to load hycu" 'taa.taa_modules=hycu' "$dcu_identity"
check_contains "dcu: the module rides with the other identity tokens" \
  "taa.taa_addr=0.0.0.0:6001 taa.taa_modules=hycu" "$dcu_identity"
check "dcu: guest RAM leaves room for the ~25 GiB DTK unpack" "61440" \
  "$(sed -n 's/^default_memory = //p' "$dcu_pkg/kata-config.toml")"
# The card has to be requested and limited; the extended resource is scheduled
# from requests, and a request without the matching limit is rejected.
python3 - "$dcu_pkg/test/test-pod.yaml" <<'PY'
import json, sys
pod = json.load(open(sys.argv[1]))
c = pod["spec"]["containers"][0]
res = c.get("resources", {})
want = {"hygon.cn/k100_ai": "1"}
problems = []
if res.get("requests") != want:
    problems.append(f"requests: {res.get('requests')}")
if res.get("limits") != want:
    problems.append(f"limits: {res.get('limits')}")
if problems:
    print("\n".join(problems), file=sys.stderr)
    sys.exit(1)
PY
echo "ok   dcu: the test Pod requests and is limited to the card"
# The CPU package must not gain either of them: its initrd ships no kmod, and
# an extended resource it never uses would keep the Pod Pending on nodes
# without a DCU.
check_absent "dcu: the CPU package names no module" 'taa.taa_modules=' \
  "$(cat "$pkg/kata-config.toml")"
check_absent "dcu: the CPU test Pod requests no card" 'hygon.cn/k100_ai' \
  "$(cat "$pkg/test/test-pod.yaml")"

# ── 5c. expected MEASUREMENT ───────────────────────────────────────────────
MEASURE="$SCRIPT_DIR/render/measure.py"
expected_cmdline="tsc=reliable no_timer_check rcupdate.rcu_expedited=1 i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 noreplace-smp reboot=k cryptomgr.notests net.ifnames=0 pci=lastbus=0 console=hvc0 console=hvc1 debug panic=1 nr_cpus=3 selinux=0 scsi_mod.scan=none agent.log=debug agent.debug_console agent.debug_console_vport=1026 rdinit=/usr/local/bin/taa-init console=ttyS0 quiet $identity_params"
rendered_cmdline="$(python3 "$MEASURE" cmdline \
  --config "$pkg/kata-config.toml" \
  --section hypervisor.qemu)"
# Kata appends the Pod's kernel_params annotation to the config's parameters,
# so the measured -append is the config-derived line plus the identity.
rendered_cmdline="$rendered_cmdline $(python3 "$RENDER" pod-kernel-params --pod "$pkg/test/test-pod.yaml")"
check "measure: cmdline follows the rendered config and Pod annotation" \
  "$expected_cmdline" "$rendered_cmdline"

# The package ships no cmdline.txt: the digest is computed here from the same
# command line the config produces, exactly as render_package does.
cmdline_file="$tmp_dir/measure-cmdline.txt"
printf '%s\n' "$rendered_cmdline" > "$cmdline_file"
measure_hex="$(python3 "$MEASURE" digest \
  --ovmf "$tmp_dir/fixture-ovmf.fd" \
  --kernel "$tmp_dir/fixture-vmlinuz" \
  --initrd "$tmp_dir/fixture-initrd.img" \
  --cmdline "$cmdline_file" | sed -n 's/^hex=//p')"
check "measure: a 64-hex digest is produced" "1" "$(grep -cE '^[0-9a-f]{64}$' <<<"$measure_hex")"
check_contains "README: shows the expected hex" "$measure_hex" "$(cat "$pkg/README.md")"
check_absent "README: no cmdline.txt reference" 'cmdline.txt' "$(cat "$pkg/README.md")"
# create-test-pod.sh carries the same SM3 and hashes-table code inline. Run that
# copy over the same inputs so a drift from the build host's measure.py is caught
# here rather than on a target host.
extract_py "$pkg/test/create-test-pod.sh" "$tmp_dir/create-measure.py"
embedded_hex="$(python3 "$tmp_dir/create-measure.py" digest \
  --ovmf "$tmp_dir/fixture-ovmf.fd" \
  --kernel "$tmp_dir/fixture-vmlinuz" \
  --initrd "$tmp_dir/fixture-initrd.img" \
  --cmdline "$cmdline_file" | sed -n 's/^hex=//p')"
check "measure: the embedded helper agrees with the build-host one" \
  "$measure_hex" "$embedded_hex"
check "package: ships no cmdline.txt" "absent" \
  "$([[ -e "$pkg/cmdline.txt" ]] && echo present || echo absent)"

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

# A package without the guest assets would install a handler pointing at files
# that are not there. The render must refuse before it touches the output
# directory, rather than publish a package that cannot boot.
for missing_input in MEASURE_KERNEL MEASURE_OVMF; do
  pkg_missing="$tmp_dir/missing-${missing_input,,}/pkg"
  out="$(env "${common_env[@]}" "$missing_input=$tmp_dir/absent.asset" \
    DIST_DIR="$pkg_missing" REMOTE_HOST=invalid.invalid "$BUILD" render 2>&1 || true)"
  check_contains "render: missing $missing_input is refused" "交付包缺少 guest 资产" "$out"
  check "render: missing $missing_input never creates the package" "absent" \
    "$([[ -e "$pkg_missing" ]] && echo present || echo absent)"
done

pkg_no_initrd="$tmp_dir/missing-initrd/pkg"
out="$(env "${common_env[@]}" INITRD_OUT="$tmp_dir/absent.initrd" \
  DIST_DIR="$pkg_no_initrd" REMOTE_HOST=invalid.invalid "$BUILD" render 2>&1 || true)"
check_contains "render: a missing built initrd points at 'build'" "initrd 由" "$out"
check "render: a missing initrd never creates the package" "absent" \
  "$([[ -e "$pkg_no_initrd" ]] && echo present || echo absent)"

if (cd "$pkg" && sha256sum -c --quiet SHA256SUMS) >/dev/null 2>&1; then
  echo "ok   SHA256SUMS verifies from inside the package"
else
  echo "FAIL SHA256SUMS does not verify" >&2
  failures=$((failures + 1))
fi

# The test Pod is the one file an operator is meant to change (its kernel_params
# annotation is the deployment identity), so a host-side identity edit must not
# look like a tampered package. Everything else stays pinned -- including the
# Kata config, which install.sh no longer rewrites.
edited_pkg="$tmp_dir/edited-pkg"
cp -a "$pkg" "$edited_pkg"
python3 - "$edited_pkg/test/test-pod.yaml" <<'PY'
import json, sys
path = sys.argv[1]
pod = json.load(open(path))
key = "io.katacontainers.config.hypervisor.kernel_params"
annotations = pod["metadata"]["annotations"]
annotations[key] = annotations[key].replace("fixture-docker-id", "host-edited")
open(path, "w").write(json.dumps(pod, indent=2) + "\n")
PY
if (cd "$edited_pkg" && sha256sum -c --quiet SHA256SUMS) >/dev/null 2>&1; then
  echo "ok   checksums: a host-side identity edit still verifies"
else
  echo "FAIL checksums: a host-side identity edit breaks verification" >&2
  failures=$((failures + 1))
fi
check_contains "checksums: the edit reached the Pod annotation" \
  'taa.docker_id=host-edited' \
  "$(extract_py "$edited_pkg/test/create-test-pod.sh" "$tmp_dir/create-py.py"; \
     python3 "$tmp_dir/create-py.py" kernel-params "$edited_pkg/test/test-pod.yaml")"

tampered_kata="$tmp_dir/tampered-kata"
cp -a "$pkg" "$tampered_kata"
printf '# tampered\n' >> "$tampered_kata/kata-config.toml"
if (cd "$tampered_kata" && sha256sum -c --quiet SHA256SUMS) >/dev/null 2>&1; then
  echo "FAIL checksums: the Kata config is supposed to be pinned" >&2
  failures=$((failures + 1))
else
  echo "ok   checksums: a modified Kata config is caught"
fi

tampered_pkg="$tmp_dir/tampered-pkg"
cp -a "$pkg" "$tampered_pkg"
printf '# tampered\n' >> "$tampered_pkg/install.sh"
if (cd "$tampered_pkg" && sha256sum -c --quiet SHA256SUMS) >/dev/null 2>&1; then
  echo "FAIL checksums: a modified immutable file should not verify" >&2
  failures=$((failures + 1))
else
  echo "ok   checksums: a modified immutable file is caught"
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
check_absent "install.sh: carries no parameter sheet" 'manifest.env' "$(cat "$pkg/install.sh")"
check_contains "install.sh: derives its settings from the package" \
  '"$taa_py" info "$pkg_dir"' "$(cat "$pkg/install.sh")"
check_contains "install.sh: carries its reader inline" \
  "cat > \"\$taa_py\" <<'TAA_PY'" "$(cat "$pkg/install.sh")"
check_absent "install.sh: calls no shipped renderer" \
  'render.py' "$(cat "$pkg/install.sh")"
check_contains "install.sh: refuses a package that does not describe itself" \
  '交付包自校验失败' "$(cat "$pkg/install.sh")"
check_contains "create script: recomputes MEASUREMENT from the running QEMU" \
  '/proc/$qpid/cmdline' "$(cat "$pkg/test/create-test-pod.sh")"
check_contains "create script: compares against the expected value" '与实际启动的 VM 一致' \
  "$(cat "$pkg/test/create-test-pod.sh")"
check_absent "install.sh: no longer re-renders the Kata config" \
  '--param-file' "$(cat "$pkg/install.sh")"
check_contains "install.sh: prints the Pod identity annotation for consumers" \
  'TEST_POD_KERNEL_PARAMS' "$(cat "$pkg/install.sh")"
check_absent "install.sh: carries no editable identity file" \
  'config/env.txt' "$(cat "$pkg/install.sh")"
check_contains "create script: includes the Pod annotation in the expectation" \
  'kernel-params "$pod_manifest"' "$(cat "$pkg/test/create-test-pod.sh")"
check_contains "create script: rebuilds the expectation from the current config" \
  '预期 MEASUREMENT (hex)' "$(cat "$pkg/test/create-test-pod.sh")"
check_absent "install.sh: no longer creates the test Pod" \
  'PACKAGE_TEST_POD' "$(cat "$pkg/install.sh")"
check_contains "install.sh: still applies the RuntimeClass" \
  'PACKAGE_RUNTIMECLASS' "$(cat "$pkg/install.sh")"
check_contains "create script: recreates the Pod so a new command line takes effect" \
  'kubectl delete pod' "$(cat "$pkg/test/create-test-pod.sh")"
# The init-data a CoCo guest needs carries this host's registry CA, so the script
# reads it from the host rather than the package carrying a per-host blob. The
# value must never end up in the rendered manifest: a package rendered on one
# host, installed on another, would then ship the wrong CA.
check_contains "create script: fills cc_init_data from the host at apply time" \
  'cc_init_data' "$(cat "$pkg/test/create-test-pod.sh")"
check_absent "create script: copies only cc_init_data, not a Pod's whole annotations" \
  'jsonpath=.{.metadata.annotations}' "$(cat "$pkg/test/create-test-pod.sh")"
check_contains "create script: verifies the measurement of the running VM" \
  '"$taa_py" digest' "$(cat "$pkg/test/create-test-pod.sh")"
check_absent "create script: calls no shipped measurement script" \
  'pkg_dir/measure.py' "$(cat "$pkg/test/create-test-pod.sh")"
check_contains "delete script: deletes the test Pod" \
  'kubectl delete pod' "$(cat "$pkg/test/delete-test-pod.sh")"
check_contains "install.sh: verifies the package first" 'sha256sum -c --quiet SHA256SUMS' "$(cat "$pkg/install.sh")"
check_contains "install.sh: preflights the prospective config" \
  '预检通过' "$(cat "$pkg/install.sh")"
check_contains "install.sh: verifies the installed drop-in in place" \
  '生效配置校验通过' "$(cat "$pkg/install.sh")"
check_contains "install.sh: owns a TAA drop-in under conf.d" \
  'zz-taa-runtimes.toml' "$(cat "$pkg/install.sh")"
check_contains "install.sh: shares one snapshot beside the packages" \
  'TAA_RUNTIMES_FILE' "$(cat "$pkg/install.sh")"
check_absent "install.sh: keeps no per-package drop-in copy" \
  'config/zz-taa-runtimes.toml' "$(cat "$pkg/install.sh")"
check_contains "install.sh: generates the drop-in as a snapshot" \
  'containerd-dropin' "$(cat "$pkg/install.sh")"
check_contains "install.sh: reuses the shared snapshot on reinstall" \
  '--base "$shared_dropin"' "$(cat "$pkg/install.sh")"
check_contains "install.sh: refuses to lose an existing handler" \
  '会丢掉已生效的 handler' "$(cat "$pkg/install.sh")"
check_contains "package: ships uninstall.sh" 'uninstall.sh' "$(cat "$pkg/README.md")"
check_contains "uninstall.sh: removes the handler from the installed drop-in" \
  'containerd-remove' "$(cat "$pkg/uninstall.sh")"
check_contains "uninstall.sh: deletes the drop-in when no TAA handler remains" \
  'TAA_HANDLER_RE' "$(cat "$pkg/uninstall.sh")"
check_contains "uninstall.sh: rewrites the same shared snapshot" \
  'TAA_RUNTIMES_FILE' "$(cat "$pkg/uninstall.sh")"
check_absent "uninstall.sh: keeps no per-package drop-in copy" \
  'config/zz-taa-runtimes.toml' "$(cat "$pkg/uninstall.sh")"
check_contains "uninstall.sh: verifies the result in place" \
  '生效配置校验通过' "$(cat "$pkg/uninstall.sh")"
check_absent "install.sh: no longer rewrites the main config" \
  'install -o root -g root -m 0644 "$tmp_containerd" "$CONTAINERD_CONFIG"' \
  "$(cat "$pkg/install.sh")"
check_absent "install.sh: no longer merges into a shared file" \
  'containerd-merge' "$(cat "$pkg/install.sh")"
check_contains "install.sh: RESTART_KUBELET is defaulted under set -u" \
  'RESTART_KUBELET="${RESTART_KUBELET:-0}"' "$(cat "$pkg/install.sh")"
check_contains "install.sh: supports dry-run" '--dry-run' "$(cat "$pkg/install.sh")"

# ── 8. render reaches the renderer without a host preflight ────────────────
drv_pkg="$tmp_dir/drv/pkg"
env "${common_env[@]}" DIST_DIR="$drv_pkg" REMOTE_HOST=invalid.invalid \
  "$BUILD" render >/dev/null
if [[ -f "$drv_pkg/kata-config.toml" && -f "$drv_pkg/install.sh" ]]; then
  echo "ok   render reaches the renderer without a host preflight"
else
  echo "FAIL render did not produce a package" >&2
  failures=$((failures + 1))
fi

# ── 9. missing template is a clear error, not a remote fetch ───────────────
out="$(env "${common_env[@]}" KATA_CONFIG_TEMPLATE="$tmp_dir/absent.toml" \
  DIST_DIR="$tmp_dir/absent-pkg" REMOTE_HOST=invalid.invalid "$BUILD" render 2>&1 || true)"
check_contains "render: missing template points at fetch-base" "fetch-base" "$out"
check "render: missing template never creates the package" "absent" \
  "$([[ -e "$tmp_dir/absent-pkg" ]] && present || echo absent)"

# ── 10. kernel-command-line identity is validated, never escaped ────────────
# A value with a space would silently become two arguments: the key would keep a
# truncated value and the guest would see a stray token. Refuse it at render time.
out="$(env "${common_env[@]}" TAA_CONTRACT_ID="two words" \
  DIST_DIR="$tmp_dir/space-pkg" REMOTE_HOST=invalid.invalid "$BUILD" render 2>&1 || true)"
check_contains "render: a whitespace value is refused" "无法写进内核命令行" "$out"
check "render: a refused value never creates the package" "absent" \
  "$([[ -e "$tmp_dir/space-pkg" ]] && echo present || echo absent)"

echo
if [[ "$failures" -eq 0 ]]; then
  echo "all checks passed"
else
  echo "$failures check(s) failed" >&2
  exit 1
fi
