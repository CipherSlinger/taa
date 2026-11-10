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
  RUNTIME_HANDLER=kata-qemu-csv2-taa-train
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

# The identity tokens render_package appends to kernel_params, in emission
# order. Kept in one place so the config and cmdline expectations cannot drift.
identity_params="taa.platform_ip=172.16.10.116:18080 taa.docker_id=fixture-docker-id taa.platform_public_key=04$(printf 'a%.0s' {1..128}) taa.platform_sm2_id=fixture-sm2-id taa.contract_id=fixture-contract-id taa.contract_type=1 taa.llm_endpoint=https://172.16.10.116:8443 taa.addr=0.0.0.0:6001"

# ── 1. render produces a self-contained package, offline ────────────────────
pkg="$tmp_dir/a/pkg"
env "${common_env[@]}" DIST_DIR="$pkg" REMOTE_HOST=invalid.invalid "$BUILD" render >/dev/null

for f in config/kata-config.toml config/env.txt config/containerd-runtime-handler.toml \
         k8s/runtimeclass.yaml test/test-pod.yaml \
         test/create-test-pod.sh test/delete-test-pod.sh SHA256SUMS \
         install.sh render.py measure.py cmdline.txt README.md \
         bundle/initramfs.img bundle/vmlinuz bundle/OVMF.fd; do
  if [[ -f "$pkg/$f" ]]; then
    echo "ok   render: produced $f"
  else
    echo "FAIL render: missing $f" >&2
    failures=$((failures + 1))
  fi
done
check "render: never contacted a host" "absent" \
  "$([[ -e "$tmp_dir/fakebin/ssh.called" || -e "$tmp_dir/fakebin/scp.called" ]] && echo called || echo absent)"
# The package is the runtime dependency: it carries the exact files QEMU boots,
# so deploying on another host needs nothing from that host's Kata tree.
check "bundle: ships the built initrd" "fixture-initrd" "$(cat "$pkg/bundle/initramfs.img")"
check "bundle: ships the kernel" "fixture-kernel" "$(cat "$pkg/bundle/vmlinuz")"
check "bundle: ships OVMF" "fixture-ovmf" "$(cat "$pkg/bundle/OVMF.fd")"

# ── 2. Kata config rewrite ─────────────────────────────────────────────────
kata="$(cat "$pkg/config/kata-config.toml")"
check_contains "kata: the image line is commented out" '# image = "/usr/share/kata-containers/kata-containers.img"' "$kata"
check_absent "kata: no active image remains" $'\nimage = ' "$kata"
check_contains "kata: kernel points at the bundle" "kernel = \"$bundle/vmlinuz\"" "$kata"
check_contains "kata: initrd points at the bundle" "initrd = \"$bundle/initramfs.img\"" "$kata"
check_contains "kata: firmware points at the bundle" "firmware = \"$bundle/OVMF.fd\"" "$kata"
check_contains "kata: rdinit is first, stale init= gone, identity appended" \
  "kernel_params = \"rdinit=/usr/local/bin/taa-init console=ttyS0 quiet $identity_params\"" "$kata"
check "kata: rdinit appears exactly once" "1" "$(grep -c 'rdinit=/usr/local/bin/taa-init' "$pkg/config/kata-config.toml")"
check_contains "kata: other sections are untouched" 'kernel_params = "must not be touched"' "$kata"
check_contains "kata: other keys in the section survive" 'burst = 10' "$kata"

# Rendering an already-rendered config is the realistic way to duplicate tokens
# (a package config reused as its own template). The key must be replaced, not
# appended a second time, and the guest parser must not be left with a stale
# value in front of the new one.
python3 "$RENDER" kata-config --template "$pkg/config/kata-config.toml" \
  --section hypervisor.qemu --bundle-dir "$bundle" \
  --param taa.platform_ip=10.0.0.1 --param taa.addr=0.0.0.0:6001 \
  --out "$tmp_dir/kata-again.toml" >/dev/null
again="$(cat "$tmp_dir/kata-again.toml")"
check "kata: a re-render never duplicates a key" "" \
  "$(grep -o 'taa\.[a-z0-9_]*=' "$tmp_dir/kata-again.toml" | sort | uniq -d)"
check "kata: a re-render keeps every identity key" "8" \
  "$(grep -o 'taa\.[a-z0-9_]*=' "$tmp_dir/kata-again.toml" | sort -u | wc -l)"
check "kata: a re-render does not stack tokens" "1" \
  "$(grep -o 'taa\.platform_ip=' "$tmp_dir/kata-again.toml" | wc -l)"
check_contains "kata: a re-render carries the new value" 'taa.platform_ip=10.0.0.1' "$again"
check_absent "kata: a re-render drops the old value" 'taa.platform_ip=172.16.10.116:18080' "$again"

# default_memory is a runtime dependency, not a tuning knob: a CSV2 guest sizes
# its writable root at about half of it and the CDH unpacks the image there. The
# override has to replace the template's value (never add a second key) and has
# to appear even when the template has none.
python3 "$RENDER" kata-config --template "$pkg/config/kata-config.toml" \
  --section hypervisor.qemu --bundle-dir "$bundle" \
  --memory-mib 23552 --out "$tmp_dir/kata-mem.toml" >/dev/null
check "memory: the override replaces the template value" "23552" \
  "$(sed -n 's/^default_memory = //p' "$tmp_dir/kata-mem.toml")"
check "memory: exactly one key survives" "1" \
  "$(grep -c '^default_memory = ' "$tmp_dir/kata-mem.toml")"

sed 's/^default_memory = .*/# default_memory removed/' "$pkg/config/kata-config.toml" > "$tmp_dir/kata-no-mem.toml"
python3 "$RENDER" kata-config --template "$tmp_dir/kata-no-mem.toml" \
  --section hypervisor.qemu --bundle-dir "$bundle" \
  --memory-mib 23552 --out "$tmp_dir/kata-mem-added.toml" >/dev/null
check "memory: a template without the key still gets the override" "23552" \
  "$(sed -n 's/^default_memory = //p' "$tmp_dir/kata-mem-added.toml")"

# ── 2b. the editable identity file ─────────────────────────────────────────
# The package ships one file an operator is meant to edit on the target host;
# install.sh re-renders the Kata config from it. What matters here is that the
# file round-trips into exactly the command line the build rendered, that edits
# take effect, and that a bad line fails instead of becoming a token the guest
# silently drops while the install reports success.
identity_file="$pkg/config/env.txt"
check "identity: the package ships config/env.txt" "present" \
  "$([[ -f "$identity_file" ]] && echo present || echo absent)"
check "identity: holds exactly the eight tokens" "$identity_params" \
  "$(grep -vE '^[[:space:]]*(#|$)' "$identity_file" | tr '\n' ' ' | sed 's/ $//')"

# Re-rendering from the delivered file must reproduce the delivered config:
# that is what makes a no-op install a no-op.
python3 "$RENDER" kata-config --template "$pkg/config/kata-config.toml" \
  --section hypervisor.qemu --bundle-dir "$bundle" \
  --param-file "$identity_file" --out "$tmp_dir/kata-from-identity.toml" >/dev/null
check "identity: re-rendering from the file is byte-identical" "same" \
  "$(cmp -s "$tmp_dir/kata-from-identity.toml" "$pkg/config/kata-config.toml" && echo same || echo different)"

# Editing a value and deleting a line are the two edits an operator makes. The
# deleted key must disappear from the command line rather than keep its old
# value, which is why --param-file replaces the whole identity set.
edited_identity="$tmp_dir/identity-edited.txt"
grep -v '^taa\.contract_type=' "$identity_file" |
  sed 's/^taa.docker_id=.*/taa.docker_id=edited-docker-id/' > "$edited_identity"
python3 "$RENDER" kata-config --template "$pkg/config/kata-config.toml" \
  --section hypervisor.qemu --bundle-dir "$bundle" \
  --param-file "$edited_identity" --out "$tmp_dir/kata-edited.toml" >/dev/null
edited_cfg="$(cat "$tmp_dir/kata-edited.toml")"
check_contains "identity: an edited value replaces the old one" 'taa.docker_id=edited-docker-id' "$edited_cfg"
check_absent "identity: the old value is gone" 'taa.docker_id=fixture-docker-id' "$edited_cfg"
check_absent "identity: a deleted line removes the parameter" 'taa.contract_type=' "$edited_cfg"
check "identity: the other keys survive" "7" \
  "$(grep -o 'taa\.[a-z0-9_]*=' "$tmp_dir/kata-edited.toml" | sort -u | wc -l)"

identity_reject() {
  local name="$1" body="$2" needle="$3"
  printf '%s\n' "$body" > "$tmp_dir/identity-bad.txt"
  rm -f "$tmp_dir/kata-bad-out.toml"
  local out
  out="$(python3 "$RENDER" kata-config --template "$pkg/config/kata-config.toml" \
    --section hypervisor.qemu --bundle-dir "$bundle" \
    --param-file "$tmp_dir/identity-bad.txt" \
    --out "$tmp_dir/kata-bad-out.toml" 2>&1 || true)"
  check_contains "$name" "$needle" "$out"
  check "  (nothing rendered)" "absent" \
    "$([[ -e "$tmp_dir/kata-bad-out.toml" ]] && echo present || echo absent)"
}

identity_reject "identity: an unknown key is refused" 'taa.unknown_key=x' 'unknown identity key'
identity_reject "identity: env-style names are refused" 'TAA_DOCKER_ID=fixture' 'unknown identity key'
identity_reject "identity: an empty value is refused" 'taa.docker_id=' 'empty value'
identity_reject "identity: a whitespace value is refused" 'taa.docker_id=two words' 'whitespace'
identity_reject "identity: a duplicate key is refused" \
  $'taa.docker_id=a\ntaa.docker_id=b' 'duplicate key'
identity_reject "identity: a line without = is refused" 'taa.docker_id' "missing '='"

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
  REMOTE_KATA_CONFIG="$image_pkg/config/kata-config.toml" \
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
  REMOTE_KATA_CONFIG="$noimg_pkg/config/kata-config.toml" \
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

# Removing what merge added must restore the fixture exactly.
cp "$tmp_dir/merged.toml" "$tmp_dir/restored.toml"
python3 "$RENDER" containerd-strip --config "$tmp_dir/restored.toml" --handler kata-qemu-csv2-taa
if cmp -s "$tmp_dir/containerd.original.toml" "$tmp_dir/restored.toml"; then
  echo "ok   merge then render.py strip restores the fixture"
else
  echo "FAIL merge then render.py strip changed the fixture" >&2
  diff -u "$tmp_dir/containerd.original.toml" "$tmp_dir/restored.toml" >&2 || true
  failures=$((failures + 1))
fi

# ── 4. Kubernetes manifests ────────────────────────────────────────────────
python3 - "$pkg/k8s/runtimeclass.yaml" "$pkg/test/test-pod.yaml" <<'PY'
import json, sys
rc = json.load(open(sys.argv[1]))
pod = json.load(open(sys.argv[2]))
problems = []
if rc.get("kind") != "RuntimeClass" or rc.get("handler") != "kata-qemu-csv2-taa-train":
    problems.append(f"runtimeclass: {rc}")
spec = pod.get("spec", {})
if spec.get("runtimeClassName") != "kata-qemu-csv2-taa-train":
    problems.append(f"runtimeClassName: {spec.get('runtimeClassName')}")
if spec.get("nodeName") != "fixture-node":
    problems.append(f"nodeName: {spec.get('nodeName')}")
container = spec.get("containers", [{}])[0]
if container.get("image") != "172.16.10.178:31313/taa-env:v1-train-infer":
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
python3 - "$pkg2/test/test-pod.yaml" <<'PY'
import json, sys
pod = json.load(open(sys.argv[1]))
spec = pod["spec"]
assert "nodeName" not in spec, "nodeName should be omitted when unknown"
assert "annotations" not in pod["metadata"], "annotations should be omitted when empty"
PY
echo "ok   k8s: unknown node and empty annotations are omitted"

# ── 5. package self-description ────────────────────────────────────────────
# The package carries no parameter sheet: install.sh asks render.py to read the
# handler, the ConfigPath and the boot assets back out of the files themselves.
# Render one where it will live, so the absolute paths resolve.
self_pkg="$tmp_dir/self/pkg"
env "${common_env[@]}" REMOTE_PACKAGE_DIR="$self_pkg" DIST_DIR="$self_pkg" \
  REMOTE_HOST=invalid.invalid "$BUILD" render >/dev/null
info="$(python3 "$self_pkg/render.py" package-info --dir "$self_pkg")"
check_contains "package-info: reports the runtime handler" "RUNTIME_HANDLER=kata-qemu-csv2-taa-train" "$info"
check_contains "package-info: reports the runtime type" \
  "RUNTIME_TYPE=io.containerd.kata-qemu-csv2.v2" "$info"
check_contains "package-info: reports the snapshotter" "SNAPSHOTTER=nydus" "$info"
check_contains "package-info: derives the bundle directory" "REMOTE_BUNDLE_DIR=$self_pkg/bundle" "$info"
check_contains "package-info: derives the ConfigPath" \
  "REMOTE_KATA_CONFIG=$self_pkg/config/kata-config.toml" "$info"
check_contains "package-info: derives the hypervisor section" \
  "KATA_HYPERVISOR_SECTION=hypervisor.qemu" "$info"
check_contains "package-info: derives the Pod name" "TEST_POD_NAME=test-kata-csv2-taa" "$info"
check_contains "package-info: derives the node name" "TEST_NODE_NAME=fixture-node" "$info"
check_contains "package-info: locates the test Pod under test/" \
  "PACKAGE_TEST_POD=test/test-pod.yaml" "$info"
check_contains "package-info: locates the RuntimeClass under k8s/" \
  "PACKAGE_RUNTIMECLASS=k8s/runtimeclass.yaml" "$info"

# A package moved after rendering names files that are no longer beside it. That
# is the check the manifest used to carry, now made from the package's own text.
moved_pkg="$tmp_dir/moved/pkg"
mkdir -p "$tmp_dir/moved"
mv "$self_pkg" "$moved_pkg"
out="$(python3 "$moved_pkg/render.py" package-info --dir "$moved_pkg" 2>&1 || true)"
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
    taa-train-dcu) want_handler=kata-qemu-hygon-dcu-csv2-taa-train; want_pkg=package-train-dcu ;;
    taa-infer-dcu) want_handler=kata-qemu-hygon-dcu-csv2-taa-infer; want_pkg=package-infer-dcu ;;
    *) want_handler=kata-qemu-csv2-$role; want_pkg=package-${role#taa-} ;;
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
dcu_kata="$(cat "$dcu_pkg/config/kata-config.toml")"
check_contains "dcu: the handler is the DCU one" \
  '"handler": "kata-qemu-hygon-dcu-csv2-taa-train"' "$(cat "$dcu_pkg/k8s/runtimeclass.yaml")"
check_contains "dcu: the runtime type extends the DCU class" \
  'runtime_type = "io.containerd.kata-qemu-hygon-dcu-csv2.v2"' \
  "$(cat "$dcu_pkg/config/containerd-runtime-handler.toml")"
check_contains "dcu: the guest is told to load hycu" 'taa.modules=hycu' "$dcu_kata"
check_contains "dcu: the module rides with the other identity tokens" \
  "taa.addr=0.0.0.0:6001 taa.modules=hycu" "$dcu_kata"
check "dcu: guest RAM matches the other large-image role" "20480" \
  "$(sed -n 's/^default_memory = //p' "$dcu_pkg/config/kata-config.toml")"
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
check_absent "dcu: the CPU package names no module" 'taa.modules=' \
  "$(cat "$pkg/config/kata-config.toml")"
check_absent "dcu: the CPU test Pod requests no card" 'hygon.cn/k100_ai' \
  "$(cat "$pkg/test/test-pod.yaml")"

# ── 5c. expected MEASUREMENT ───────────────────────────────────────────────
MEASURE="$SCRIPT_DIR/render/measure.py"
expected_cmdline="tsc=reliable no_timer_check rcupdate.rcu_expedited=1 i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 noreplace-smp reboot=k cryptomgr.notests net.ifnames=0 pci=lastbus=0 console=hvc0 console=hvc1 debug panic=1 nr_cpus=3 selinux=0 scsi_mod.scan=none agent.log=debug agent.debug_console agent.debug_console_vport=1026 rdinit=/usr/local/bin/taa-init console=ttyS0 quiet $identity_params"
check "measure: cmdline follows the rendered config" "$expected_cmdline" "$(cat "$pkg/cmdline.txt")"

measure_hex="$(python3 "$MEASURE" digest \
  --ovmf "$tmp_dir/fixture-ovmf.fd" \
  --kernel "$tmp_dir/fixture-vmlinuz" \
  --initrd "$tmp_dir/fixture-initrd.img" \
  --cmdline "$pkg/cmdline.txt" | sed -n 's/^hex=//p')"
check "measure: a 64-hex digest is produced" "1" "$(grep -cE '^[0-9a-f]{64}$' <<<"$measure_hex")"
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

# The two files an operator is meant to change are excluded from the checksums,
# so a host-side identity edit must not look like a tampered package. Everything
# else stays pinned: the edit is narrow on purpose.
edited_pkg="$tmp_dir/edited-pkg"
cp -a "$pkg" "$edited_pkg"
sed -i 's/^taa\.docker_id=.*/taa.docker_id=host-edited/' "$edited_pkg/config/env.txt"
python3 "$edited_pkg/render.py" kata-config --template "$edited_pkg/config/kata-config.toml" \
  --section hypervisor.qemu --bundle-dir "$bundle" \
  --param-file "$edited_pkg/config/env.txt" \
  --out "$edited_pkg/config/kata-config.toml" >/dev/null
if (cd "$edited_pkg" && sha256sum -c --quiet SHA256SUMS) >/dev/null 2>&1; then
  echo "ok   checksums: a host-side identity edit still verifies"
else
  echo "FAIL checksums: a host-side identity edit breaks verification" >&2
  failures=$((failures + 1))
fi
check_contains "checksums: the edit reached the rendered config" \
  'taa.docker_id=host-edited' "$(cat "$edited_pkg/config/kata-config.toml")"

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
  'package-info --dir' "$(cat "$pkg/install.sh")"
check_contains "install.sh: refuses a package that does not describe itself" \
  '交付包自校验失败' "$(cat "$pkg/install.sh")"
check_contains "create script: recomputes MEASUREMENT from the running QEMU" \
  '/proc/$qpid/cmdline' "$(cat "$pkg/test/create-test-pod.sh")"
check_contains "create script: compares against the expected value" '与实际启动的 VM 一致' \
  "$(cat "$pkg/test/create-test-pod.sh")"
check_contains "install.sh: re-renders from the editable identity" \
  '--param-file "$identity_file"' "$(cat "$pkg/install.sh")"
check_contains "create script: rebuilds the expectation from the current config" \
  '预期 MEASUREMENT (hex)' "$(cat "$pkg/test/create-test-pod.sh")"
check_absent "install.sh: no longer creates the test Pod" \
  'test-pod.yaml' "$(cat "$pkg/install.sh")"
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
  'measure.py" digest' "$(cat "$pkg/test/create-test-pod.sh")"
check_contains "delete script: deletes the test Pod" \
  'kubectl delete pod' "$(cat "$pkg/test/delete-test-pod.sh")"
check_contains "install.sh: verifies the package first" 'sha256sum -c --quiet SHA256SUMS' "$(cat "$pkg/install.sh")"
check_contains "install.sh: checks the effective config, imports included" \
  '生效的 containerd 配置里' "$(cat "$pkg/install.sh")"
check_contains "install.sh: supports dry-run" '--dry-run' "$(cat "$pkg/install.sh")"

# ── 8. render reaches the renderer without a host preflight ────────────────
drv_pkg="$tmp_dir/drv/pkg"
env "${common_env[@]}" DIST_DIR="$drv_pkg" REMOTE_HOST=invalid.invalid \
  "$BUILD" render >/dev/null
if [[ -f "$drv_pkg/config/kata-config.toml" && -f "$drv_pkg/install.sh" ]]; then
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
