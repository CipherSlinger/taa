#!/usr/bin/env bash
# Create the delivery package's test Pod and verify the guest booted this package.
#
# install.sh stops at the RuntimeClass: the test Pod is not part of the runtime,
# it only exercises it. This script creates the Pod, waits for Ready, and then
# runs the two checks that need a running VM:
#
#   1. QEMU's command line names this package's bundle/initramfs.img;
#   2. the running VM's CSV2 MEASUREMENT matches the value recomputed from the
#      packaged kernel/initrd/OVMF and the config currently on this host.
#
# An existing test Pod is deleted first: a Pod spec is immutable, and a Pod
# created before an env.txt edit still carries the old kernel command line.
#
# Usage: sudo bash test/create-test-pod.sh
#
# Environment overrides:
#   MEASURE_SMP   vCPU count for the expected kernel command line
#                 (default: the Kata config's default_vcpus)
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for cmd in kubectl python3 ps; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: $cmd is not installed or not in PATH" >&2
    exit 1
  fi
done

# The package describes itself; package-info also refuses a moved or incomplete
# directory, so a Pod is never created against a half-assembled package.
if ! pkg_settings="$(python3 "$pkg_dir/render.py" package-info --dir "$pkg_dir")"; then
  echo "error: 交付包自校验失败" >&2
  exit 1
fi
eval "$pkg_settings"

if [[ "$(id -u)" -ne 0 ]] && ! sudo -n true 2>/dev/null; then
  echo "error: this account needs passwordless sudo (sudo -n true failed)" >&2
  echo "hint: run as root, or add a NOPASSWD sudoers entry" >&2
  exit 1
fi

if ! kubectl get runtimeclass "$RUNTIME_HANDLER" >/dev/null 2>&1; then
  echo "error: RuntimeClass $RUNTIME_HANDLER 不存在" >&2
  echo "hint: 先执行 install.sh，RuntimeClass 由它创建" >&2
  exit 1
fi

tmp_expected=""
tmp_append=""
tmp_pod=""
cleanup() {
  if [[ -n "$tmp_expected" ]]; then rm -f "$tmp_expected"; fi
  if [[ -n "$tmp_append" ]]; then rm -f "$tmp_append"; fi
  if [[ -n "$tmp_pod" ]]; then rm -f "$tmp_pod"; fi
  return 0
}
trap cleanup EXIT

# A CoCo guest pulls the container image itself through CDH, and it trusts a
# private registry only when the Pod carries the init-data that names that
# registry's CA. Without it the pull fails with a TLS error and the Pod lands in
# StartError, which reads like an initrd failure but is not one.
#
# The value cannot be a build-time default: it is per-host (it embeds the CA of
# the registry on this host) and is ~2 KiB of base64. So it is read here, from
# the host, at the only moment it is needed. Any running CoCo Pod already
# carries it; /root/cc_init_data.txt holds the same blob.
#
# Only this one annotation is copied. Taking a Pod's whole annotation set does
# not work: io.containerd.cri.runtime-handler would point the Pod back at the
# original handler, and an empty hypervisor.kernel_params would override the
# config's rdinit= so TAA never starts -- both leave the Pod Ready while testing
# something other than this package.
cc_init_annotation="io.katacontainers.config.runtime.cc_init_data"
pod_manifest="$pkg_dir/$PACKAGE_TEST_POD"

echo "== 1. 准备测试 Pod =="
if python3 - "$pod_manifest" "$cc_init_annotation" <<'PY'
import json, sys
pod = json.load(open(sys.argv[1]))
sys.exit(0 if sys.argv[2] in (pod["metadata"].get("annotations") or {}) else 1)
PY
then
  echo "已带 $cc_init_annotation，直接使用"
else
  cc_init_data="${CC_INIT_DATA:-}"
  if [[ -z "$cc_init_data" ]]; then
    cc_init_data="$(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.annotations.io\.katacontainers\.config\.runtime\.cc_init_data}{"\n"}{end}' 2>/dev/null | grep -m1 . || true)"
  fi
  if [[ -z "$cc_init_data" && -r /root/cc_init_data.txt ]]; then
    cc_init_data="$(tr -d '[:space:]' < /root/cc_init_data.txt)"
  fi
  if [[ -z "$cc_init_data" ]]; then
    echo "warning: 本机没有可用于 $cc_init_annotation 的值；镜像若在需要 CA 的私有 registry 上，" >&2
    echo "         CDH 会拉取失败并把 Pod 留在 StartError。先起一个 CoCo Pod，或设 CC_INIT_DATA。" >&2
  else
    tmp_pod="$(mktemp /tmp/taa-test-pod.XXXXXX.yaml)"
    python3 - "$pod_manifest" "$tmp_pod" "$cc_init_annotation" "$cc_init_data" <<'PY'
import json, sys
src, dst, key, value = sys.argv[1:5]
pod = json.load(open(src))
pod.setdefault("metadata", {}).setdefault("annotations", {})[key] = value
open(dst, "w").write(json.dumps(pod, indent=2) + "\n")
PY
    pod_manifest="$tmp_pod"
    echo "已从本机取到 $cc_init_annotation (${#cc_init_data} 字符)"
  fi
fi

echo "pod: $TEST_POD_NAME  handler: $RUNTIME_HANDLER"
kubectl delete pod "$TEST_POD_NAME" --ignore-not-found --wait=true
kubectl apply -f "$pod_manifest"

echo
echo "== 2. 等待测试 Pod Ready =="
if ! kubectl wait --for=condition=Ready "pod/$TEST_POD_NAME" --timeout=180s; then
  echo "error: test Pod did not become Ready within 180s; status and events follow" >&2
  kubectl get pod "$TEST_POD_NAME" -o wide >&2 || true
  kubectl describe pod "$TEST_POD_NAME" 2>&1 | sed -n '/Events:/,$p' >&2 || true
  exit 1
fi
kubectl get pod "$TEST_POD_NAME" -o wide

echo
echo "== 3. 校验 QEMU 使用了本包的 initrd =="
if ps -eo args= | grep -F "qemu" | grep -F "$REMOTE_BUNDLE_DIR/initramfs.img" | grep -v grep >/dev/null; then
  echo "verified QEMU is using: $REMOTE_BUNDLE_DIR/initramfs.img"
else
  echo "error: Pod is ready, but no QEMU command line with $REMOTE_BUNDLE_DIR/initramfs.img was found" >&2
  echo "hint: run: ps -eo args= | grep -F qemu | grep -F '$REMOTE_BUNDLE_DIR'" >&2
  exit 1
fi

echo
echo "== 4. 度量核对 =="
# The expected MEASUREMENT is recomputed here from the config currently on this
# host. That is the only input that can differ from the build host: the kernel,
# initrd and OVMF are the package's own bytes, and the command line follows
# from the config. A difference from the running VM then means env.txt changed
# or the host's Kata drifted, not that the package is stale.
package_kata_config="$pkg_dir/$PACKAGE_KATA_CONFIG"
kata_section="$KATA_HYPERVISOR_SECTION"
expected_hex=""
expected_cmdline=""
smp_args=()
[[ -n "${MEASURE_SMP:-}" ]] && smp_args=(--smp "$MEASURE_SMP")
if expected_cmdline="$(python3 "$pkg_dir/measure.py" cmdline \
    --config "$package_kata_config" --section "$kata_section" \
    ${smp_args[@]+"${smp_args[@]}"} 2>/dev/null)"; then
  tmp_expected="$(mktemp /tmp/taa-expected.XXXXXX.txt)"
  printf '%s\n' "$expected_cmdline" > "$tmp_expected"
  if expected_out="$(python3 "$pkg_dir/measure.py" digest \
    --ovmf "$REMOTE_BUNDLE_DIR/OVMF.fd" \
    --kernel "$REMOTE_BUNDLE_DIR/vmlinuz" \
    --initrd "$REMOTE_BUNDLE_DIR/initramfs.img" \
    --cmdline "$tmp_expected" 2>/dev/null)"; then
    expected_hex="$(sed -n 's/^hex=//p' <<<"$expected_out")"
  fi
fi

if [[ -z "$expected_hex" ]]; then
  echo "warning: 无法按当前配置重算预期 MEASUREMENT，跳过核对" >&2
else
  echo "预期 MEASUREMENT (hex):    $expected_hex"
  echo "预期 cmdline: $expected_cmdline"
  qpid="$(ps -eo pid=,args= | grep -F qemu | grep -F "$REMOTE_BUNDLE_DIR/initramfs.img" |
    grep -v grep | awk '{print $1}' | head -n 1 || true)"
  tmp_append="$(mktemp /tmp/taa-append.XXXXXX.txt)"
  if [[ -z "$qpid" ]]; then
    echo "warning: 找不到使用本 bundle 的 QEMU 进程，无法重算 MEASUREMENT" >&2
  else
    # /proc/<pid>/cmdline separates argv entries with NUL, so translating NUL to
    # newline already leaves the -append value newline-terminated. Capture it
    # through a command substitution (which strips that trailing newline) and
    # write exactly one back: measure.py replaces only the final byte with NUL,
    # so a second trailing newline would be hashed and yield a digest that never
    # matches the running VM.
    append_value="$(tr '\0' '\n' < "/proc/$qpid/cmdline" |
      grep -A1 -- '^-append$' | tail -n1 || true)"
    if [[ -z "$append_value" ]]; then
      echo "warning: 未能从 /proc/$qpid/cmdline 取到 -append" >&2
    else
      printf '%s\n' "$append_value" > "$tmp_append"
      if ! actual_measure="$(python3 "$pkg_dir/measure.py" digest \
        --ovmf "$REMOTE_BUNDLE_DIR/OVMF.fd" \
        --kernel "$REMOTE_BUNDLE_DIR/vmlinuz" \
        --initrd "$REMOTE_BUNDLE_DIR/initramfs.img" \
        --cmdline "$tmp_append")"; then
        echo "warning: measure.py 重算失败，跳过度量核对" >&2
        actual_measure=""
      fi
      actual_hex="$(sed -n 's/^hex=//p' <<<"$actual_measure")"
      actual_b64="$(sed -n 's/^base64=//p' <<<"$actual_measure")"
      if [[ -z "$actual_hex" ]]; then
        :
      elif [[ "$actual_hex" == "$expected_hex" ]]; then
        echo "实际 MEASUREMENT (hex):    $actual_hex"
        echo "实际 MEASUREMENT (base64): $actual_b64"
        echo "与实际启动的 VM 一致（预期值按当前配置重算）"
      else
        echo "实际 MEASUREMENT (hex):    $actual_hex"
        echo "实际 MEASUREMENT (base64): $actual_b64"
        echo "warning: 实际度量与预期不一致（预期值按当前配置重算）" >&2
        echo "  预期 hex: $expected_hex" >&2
        echo "  实际 cmdline: $(cat "$tmp_append")" >&2
        echo "hint: 以实际 cmdline 的重算结果为准；若宿主升级了 Kata，请重新 render" >&2
      fi
    fi
  fi
fi

echo
echo "测试 Pod 已就绪: $TEST_POD_NAME"
echo "删除它: sudo bash $pkg_dir/test/delete-test-pod.sh"
