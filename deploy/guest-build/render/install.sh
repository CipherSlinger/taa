#!/usr/bin/env bash
# Install the TAA-in-initrd delivery package on a Kata CSV2 host.
#
# The package is produced by `build-initrd.sh render` (or by `launch`, which
# renders the same files first). This script never generates anything: it
# verifies the package and the host, installs the rendered Kata config, merges
# the containerd runtime handler, and creates the test Pod.
#
# Usage: sudo bash install.sh [--dry-run] [--skip-template-check] [--skip-base-check]
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="$pkg_dir/manifest.env"
dry_run=0
skip_template_check=0
skip_base_check=0

for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    --skip-template-check) skip_template_check=1 ;;
    --skip-base-check) skip_base_check=1 ;;
    -h|--help)
      sed -n '2,11p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "error: unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "$manifest" ]]; then
  echo "error: missing $manifest (run install.sh from the package root)" >&2
  exit 1
fi
# Every value is %q-quoted by the renderer, so source is safe.
source "$manifest"

run() {
  if [[ "$dry_run" == "1" ]]; then
    printf 'dry-run: %s\n' "$*"
  else
    "$@"
  fi
}

echo "== 1. 校验包与宿主依赖 =="

for cmd in kubectl sudo python3 containerd grep ps sha256sum cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: $cmd is not installed or not in PATH" >&2
    exit 1
  fi
done

if [[ "$(id -u)" -ne 0 ]] && ! sudo -n true 2>/dev/null; then
  echo "error: this account needs passwordless sudo (sudo -n true failed)" >&2
  echo "hint: run as root, or add a NOPASSWD sudoers entry" >&2
  exit 1
fi

(cd "$pkg_dir" && sha256sum -c --quiet SHA256SUMS)
echo "包校验通过: $pkg_dir"

if [[ ! -f "$CONTAINERD_CONFIG" ]]; then
  echo "error: containerd config not found: $CONTAINERD_CONFIG" >&2
  exit 1
fi
if ! grep -qE '^[[:space:]]*version[[:space:]]*=[[:space:]]*2([[:space:]]|$)' "$CONTAINERD_CONFIG"; then
  echo "error: unsupported containerd config format in $CONTAINERD_CONFIG (need version = 2)" >&2
  exit 1
fi

# The rendered Kata config is derived from this host's shipped CSV2 config.
# A mismatch means the package was built against a different Kata version and
# its kernel/initrd paths may not be the ones this host expects.
if [[ -f "$KATA_CONFIG_TEMPLATE_SRC" ]]; then
  template_sha="$(sha256sum "$KATA_CONFIG_TEMPLATE_SRC" | awk '{print $1}')"
  if [[ "$template_sha" != "$KATA_CONFIG_TEMPLATE_SHA256" ]]; then
    if [[ "$skip_template_check" != "1" ]]; then
      echo "error: Kata 配置模板与本包不一致" >&2
      echo "       包:   $KATA_CONFIG_TEMPLATE_SHA256" >&2
      echo "       宿主: $template_sha  $KATA_CONFIG_TEMPLATE_SRC" >&2
      echo "hint: 在模板来源宿主上重新 render，或加 --skip-template-check 明确承担风险" >&2
      exit 1
    fi
    echo "warning: --skip-template-check，Kata 配置模板不一致，继续" >&2
  else
    echo "Kata 配置模板一致: $template_sha"
  fi
else
  echo "error: 宿主缺少 Kata CSV2 模板: $KATA_CONFIG_TEMPLATE_SRC" >&2
  echo "hint: 该宿主不是本包的部署目标，或 Kata 安装路径不同" >&2
  exit 1
fi

# The base initrd is not used at runtime, only by `deploy`; a missing copy is
# a warning, but a different copy means the delivered initrd's measurement
# basis is not this host's.
if [[ -f "$BASE_INITRD_SRC" ]]; then
  base_sha="$(sha256sum "$BASE_INITRD_SRC" | awk '{print $1}')"
  if [[ "$base_sha" != "$BASE_INITRD_SHA256" ]]; then
    if [[ "$skip_base_check" != "1" ]]; then
      echo "error: 宿主的 base initrd 与构建时不一致，度量基准可能已漂移" >&2
      echo "       包:   $BASE_INITRD_SHA256" >&2
      echo "       宿主: $base_sha  $BASE_INITRD_SRC" >&2
      echo "hint: 加 --skip-base-check 明确承担风险" >&2
      exit 1
    fi
    echo "warning: --skip-base-check，base initrd 不一致，继续" >&2
  else
    echo "base initrd 一致: $base_sha"
  fi
else
  echo "warning: 宿主没有 $BASE_INITRD_SRC（运行期不需要，deploy 时需要）" >&2
fi

for asset in initramfs.img vmlinuz OVMF.fd; do
  if [[ ! -f "$REMOTE_BUNDLE_DIR/$asset" ]]; then
    echo "error: bundle 缺少 $asset: $REMOTE_BUNDLE_DIR/$asset" >&2
    echo "hint: 先在该宿主上运行 build-initrd.sh deploy（或手工放置 bundle）" >&2
    exit 1
  fi
done
# The predicted MEASUREMENT was computed from exactly these three files. A
# mismatch means the host would boot different bytes than the package claims.
for spec in "initramfs.img:$INITRD_SHA256" "vmlinuz:$KERNEL_SHA256" "OVMF.fd:$OVMF_SHA256"; do
  asset="${spec%%:*}"
  expected="${spec#*:}"
  [[ -z "$expected" ]] && continue
  bundle_sha="$(sha256sum "$REMOTE_BUNDLE_DIR/$asset" | awk '{print $1}')"
  if [[ "$bundle_sha" != "$expected" ]]; then
    echo "error: bundle/$asset 与本包记录的摘要不一致" >&2
    echo "       包:     $expected" >&2
    echo "       bundle: $bundle_sha  $REMOTE_BUNDLE_DIR/$asset" >&2
    echo "hint: 重新部署与包匹配的 bundle，或重新 render 生成与宿主一致的包" >&2
    exit 1
  fi
  echo "bundle $asset 一致: $bundle_sha"
done

if [[ -n "$TEST_NODE_NAME" ]]; then
  if ! kubectl get node "$TEST_NODE_NAME" >/dev/null 2>&1; then
    echo "error: TEST_NODE_NAME does not exist: $TEST_NODE_NAME" >&2
    exit 1
  fi
fi

echo
echo "== 2. 安装 Kata 配置 =="
run sudo mkdir -p "${REMOTE_KATA_CONFIG%/*}"
run sudo install -o root -g root -m 0644 "$pkg_dir/$PACKAGE_KATA_CONFIG" "$REMOTE_KATA_CONFIG"
echo "Kata guest assets in $REMOTE_KATA_CONFIG:"
grep -nE '^[[:space:]]*(kernel|initrd|firmware|kernel_params)[[:space:]]*=' "$pkg_dir/$PACKAGE_KATA_CONFIG"

echo
echo "== 3. 合并 containerd runtime handler =="
tmp_containerd="$(mktemp /tmp/containerd-config.taa.XXXXXX.toml)"
containerd_backup=""
cleanup() {
  rm -f "$tmp_containerd"
  if [[ -n "${append_file:-}" ]]; then
    rm -f "$append_file"
  fi
  if [[ -n "$containerd_backup" ]]; then
    sudo rm -f "$containerd_backup" || true
  fi
}
trap cleanup EXIT

cp "$CONTAINERD_CONFIG" "$tmp_containerd"
python3 "$pkg_dir/render.py" containerd-merge \
  --config "$tmp_containerd" \
  --handler "$RUNTIME_HANDLER" \
  --runtime-type "$RUNTIME_TYPE" \
  --runtime-path "$RUNTIME_PATH" \
  --snapshotter "$SNAPSHOTTER" \
  --kata-config "$REMOTE_KATA_CONFIG"

handler_header="[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.\"$RUNTIME_HANDLER\"]"
handler_options="[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.\"$RUNTIME_HANDLER\".options]"
for expected in "$handler_header" "$handler_options" "ConfigPath = \"$REMOTE_KATA_CONFIG\""; do
  if ! grep -qF "$expected" "$tmp_containerd"; then
    echo "error: containerd 配置缺少预期内容: $expected" >&2
    exit 1
  fi
done
if ! sudo containerd --config "$tmp_containerd" config dump >/dev/null; then
  echo "error: 生成的 containerd 配置无效，未改动宿主配置" >&2
  exit 1
fi

if sudo cmp -s "$tmp_containerd" "$CONTAINERD_CONFIG"; then
  echo "containerd 配置未变化，跳过重启"
else
  echo "重启 containerd"
  containerd_backup="$(mktemp /tmp/containerd-config.backup.XXXXXX.toml)"
  sudo cp -a "$CONTAINERD_CONFIG" "$containerd_backup"
  run sudo install -o root -g root -m 0644 "$tmp_containerd" "$CONTAINERD_CONFIG"
  if [[ "$dry_run" != "1" ]]; then
    if ! sudo systemctl restart containerd || ! sudo systemctl is-active --quiet containerd; then
      sudo journalctl -u containerd -n 50 --no-pager >&2 || true
      echo "error: containerd 重启失败，回滚配置" >&2
      sudo install -o root -g root -m 0644 "$containerd_backup" "$CONTAINERD_CONFIG"
      sudo systemctl restart containerd || true
      exit 1
    fi
    if [[ "$RESTART_KUBELET" == "1" ]]; then
      echo "重启 kubelet"
      sudo systemctl restart kubelet
      if ! sudo systemctl is-active --quiet kubelet; then
        sudo journalctl -u kubelet -n 50 --no-pager >&2 || true
        echo "error: kubelet is not active after restart" >&2
        exit 1
      fi
    fi
    sudo rm -f "$containerd_backup"
    containerd_backup=""
    echo "containerd 已重启"
  fi
fi

echo
echo "== 4. 创建 RuntimeClass 与测试 Pod =="
run kubectl apply -f "$pkg_dir/k8s/runtimeclass.yaml"
run kubectl delete pod "$TEST_POD_NAME" --ignore-not-found --wait=true
run kubectl apply -f "$pkg_dir/k8s/test-pod.yaml"

if [[ "$dry_run" == "1" ]]; then
  echo "dry-run: kubectl wait --for=condition=Ready pod/$TEST_POD_NAME --timeout=180s"
  echo "dry-run: 跳过 QEMU initrd 校验"
  echo "dry-run 结束：以上内容尚未安装"
  exit 0
fi

echo
echo "== 5. 等待测试 Pod Ready =="
if ! kubectl wait --for=condition=Ready "pod/$TEST_POD_NAME" --timeout=180s; then
  echo "error: test Pod did not become Ready within 180s; status and events follow" >&2
  kubectl get pod "$TEST_POD_NAME" -o wide >&2 || true
  kubectl describe pod "$TEST_POD_NAME" 2>&1 | sed -n '/Events:/,$p' >&2 || true
  exit 1
fi
kubectl get pod "$TEST_POD_NAME" -o wide

echo
echo "== 6. 校验 QEMU 使用了本包的 initrd =="
if ps -eo args= | grep -F "qemu" | grep -F "$REMOTE_BUNDLE_DIR/initramfs.img" | grep -v grep >/dev/null; then
  echo "verified QEMU is using: $REMOTE_BUNDLE_DIR/initramfs.img"
else
  echo "error: Pod is ready, but no QEMU command line with $REMOTE_BUNDLE_DIR/initramfs.img was found" >&2
  echo "hint: run: ps -eo args= | grep -F qemu | grep -F '$REMOTE_BUNDLE_DIR'" >&2
  exit 1
fi

echo
echo "== 7. 度量核对 =="
if [[ -z "${MEASUREMENT_HEX:-}" ]]; then
  echo "包内未包含预期 MEASUREMENT，跳过核对"
else
  qpid="$(ps -eo pid=,args= | grep -F qemu | grep -F "$REMOTE_BUNDLE_DIR/initramfs.img" |
    grep -v grep | awk '{print $1}' | head -n 1 || true)"
  append_file="$(mktemp /tmp/taa-append.XXXXXX.txt)"
  if [[ -z "$qpid" ]]; then
    echo "warning: 找不到使用本 bundle 的 QEMU 进程，无法重算 MEASUREMENT" >&2
  else
    tr '\0' '\n' < "/proc/$qpid/cmdline" | grep -A1 -- '^-append$' | tail -n1 > "$append_file" || true
    if [[ ! -s "$append_file" ]]; then
      echo "warning: 未能从 /proc/$qpid/cmdline 取到 -append" >&2
    else
      # measure.py replaces the trailing newline with NUL, like the vendor tool.
      printf '\n' >> "$append_file"
      if ! actual_measure="$(python3 "$pkg_dir/measure.py" digest \
        --ovmf "$REMOTE_BUNDLE_DIR/OVMF.fd" \
        --kernel "$REMOTE_BUNDLE_DIR/vmlinuz" \
        --initrd "$REMOTE_BUNDLE_DIR/initramfs.img" \
        --cmdline "$append_file")"; then
        echo "warning: measure.py 重算失败，跳过度量核对" >&2
        actual_measure=""
      fi
      actual_hex="$(sed -n 's/^hex=//p' <<<"$actual_measure")"
      actual_b64="$(sed -n 's/^base64=//p' <<<"$actual_measure")"
      if [[ -z "$actual_hex" ]]; then
        :
      elif [[ "$actual_hex" == "$MEASUREMENT_HEX" ]]; then
        echo "实际 MEASUREMENT (hex):    $actual_hex"
        echo "实际 MEASUREMENT (base64): $actual_b64"
        echo "与包内预期一致"
      else
        echo "实际 MEASUREMENT (hex):    $actual_hex"
        echo "实际 MEASUREMENT (base64): $actual_b64"
        echo "warning: 实际度量与本包预期不一致" >&2
        echo "  预期 hex: $MEASUREMENT_HEX" >&2
        echo "  实际 cmdline: $(cat "$append_file")" >&2
        echo "hint: 以实际 cmdline 的重算结果为准；若宿主升级了 Kata，请重新 render" >&2
      fi
    fi
  fi
fi

echo
echo "安装完成。使用方创建 Pod 时指定 runtimeClassName: $RUNTIME_HANDLER"
