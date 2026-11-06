#!/usr/bin/env bash
# Install the TAA-in-initrd delivery package on a Kata CSV2 host.
#
# The package is produced by `build-initrd.sh render` (or by `launch`, which
# renders the same files first). This script re-renders the Kata config from the
# editable `config/identity.txt`, merges the containerd runtime handler, and
# creates the test Pod.
#
# Every setting is derived from the package itself -- the runtime handler and
# its ConfigPath from config/containerd-runtime-handler.toml, the boot assets
# from config/kata-config.toml. render.py package-info reads both and refuses a
# package whose absolute paths do not name its own files, so a moved or
# half-assembled directory fails before anything is touched.
#
# To change the deployment identity (platform address, docker id, public key,
# LLM endpoint, ...) edit config/identity.txt and re-run this script. No
# rebuild and no re-upload: the initrd's bytes, and with them its measurement
# basis, stay as they are; only the measured kernel command line changes.
#
# Usage: sudo bash install.sh [--dry-run]
#
# Environment overrides:
#   CONTAINERD_CONFIG   containerd config to merge the handler into
#                       (default /etc/containerd/config.toml)
#   RESTART_KUBELET     1 also restarts kubelet after containerd (default 0)
#   MEASURE_SMP         vCPU count for the expected kernel command line
#                       (default: the Kata config's default_vcpus)
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dry_run=0

for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    -h|--help)
      sed -n '2,/^set -euo pipefail$/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "error: unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

CONTAINERD_CONFIG="${CONTAINERD_CONFIG:-/etc/containerd/config.toml}"
RESTART_KUBELET="${RESTART_KUBELET:-0}"

tmp_kata_config=""
tmp_containerd=""
containerd_backup=""
append_file=""
cleanup() {
  if [[ -n "$tmp_kata_config" ]]; then rm -f "$tmp_kata_config"; fi
  if [[ -n "$tmp_containerd" ]]; then rm -f "$tmp_containerd"; fi
  if [[ -n "$append_file" ]]; then rm -f "$append_file"; fi
  if [[ -n "$containerd_backup" ]]; then sudo rm -f "$containerd_backup" || true; fi
  return 0
}
trap cleanup EXIT

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

# The package describes itself: the handler block and the Kata config name
# every path the installer uses, and package_info refuses the ones that do not
# resolve to this directory. Nothing below needs a parameter sheet.
if ! pkg_settings="$(python3 "$pkg_dir/render.py" package-info --dir "$pkg_dir")"; then
  echo "error: 交付包自校验失败，未改动宿主" >&2
  exit 1
fi
# package-info quotes every value, so eval is safe.
eval "$pkg_settings"

# curl and docker are needed only to place the Pod image into its registry, so
# they are required only when the package ships an archive: curl probes the
# registry, docker imports the archive and pushes it.
if [[ -n "$TEST_IMAGE_ARCHIVE" ]]; then
  for cmd in curl docker; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "error: 包内带有镜像归档，但宿主缺少 $cmd" >&2
      exit 1
    fi
  done
fi
kata_section="$KATA_HYPERVISOR_SECTION"
identity_file="$pkg_dir/$PACKAGE_IDENTITY_FILE"
echo "runtime handler: $RUNTIME_HANDLER (ConfigPath $REMOTE_KATA_CONFIG)"

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

if [[ -n "$TEST_NODE_NAME" ]]; then
  if ! kubectl get node "$TEST_NODE_NAME" >/dev/null 2>&1; then
    echo "error: TEST_NODE_NAME does not exist: $TEST_NODE_NAME" >&2
    exit 1
  fi
fi

echo
echo "== 2. Kata 配置（按 config/identity.txt 重新渲染）=="
package_kata_config="$pkg_dir/$PACKAGE_KATA_CONFIG"
if [[ ! -f "$package_kata_config" ]]; then
  echo "error: 包内 Kata 配置缺失: $package_kata_config" >&2
  exit 1
fi

if [[ -f "$identity_file" ]]; then
  echo "部署身份 (config/identity.txt):"
  grep -vE '^[[:space:]]*(#|$)' "$identity_file" | sed 's/^/  /'
  tmp_kata_config="$(mktemp /tmp/kata-config.taa.XXXXXX.toml)"
  if ! python3 "$pkg_dir/render.py" kata-config \
    --template "$package_kata_config" \
    --section "$kata_section" \
    --bundle-dir "$REMOTE_BUNDLE_DIR" \
    --param-file "$identity_file" \
    --out "$tmp_kata_config"; then
    echo "error: 按 config/identity.txt 渲染 Kata 配置失败，未改动宿主配置" >&2
    exit 1
  fi
  if cmp -s "$tmp_kata_config" "$package_kata_config"; then
    echo "与交付时一致，Kata 配置无需更新"
  else
    echo "身份已修改，更新 $PACKAGE_KATA_CONFIG"
    run sudo install -o root -g root -m 0644 "$tmp_kata_config" "$package_kata_config"
  fi
else
  echo "warning: 包内没有 config/identity.txt，沿用交付时的 Kata 配置" >&2
fi

# The handler's ConfigPath points at the packaged copy (package_info verified
# it), so there is nothing to install under /etc: the package is the host's only
# copy, and install(1) would refuse anyway ("are the same file").
echo "Kata 配置即交付包内文件，无需安装: $REMOTE_KATA_CONFIG"
echo "Kata guest assets in $REMOTE_KATA_CONFIG:"
grep -nE '^[[:space:]]*(kernel|initrd|firmware|kernel_params)[[:space:]]*=' "$package_kata_config"

echo
echo "== 3. 合并 containerd runtime handler =="
tmp_containerd="$(mktemp /tmp/containerd-config.taa.XXXXXX.toml)"

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
echo "== 4. 确保 test Pod 镜像已进 registry =="
# A CoCo guest pulls the container image itself through CDH; the host's docker
# daemon is not in that path, so `docker load` alone leaves the Pod in
# StartError with an image-pull error. The package therefore ships the image as
# a `docker save` archive, and it has to end up in the registry the Pod names.
#
# The check is on the registry, not on local docker images: a host that already
# has the tag locally can still have a Pod failing, because CDH never looks
# there. Only when the registry answers 404 is the archive loaded and pushed.
if [[ -n "$TEST_IMAGE_ARCHIVE" ]]; then
  image_archive="$pkg_dir/$TEST_IMAGE_ARCHIVE"
  if [[ ! -f "$image_archive" ]]; then
    echo "error: 包内声明的镜像归档不存在: $image_archive" >&2
    exit 1
  fi
  image_repo="${TEST_IMAGE%:*}"
  image_tag="${TEST_IMAGE##*:}"
  registry_host="${image_repo%%/*}"
  if [[ "$registry_host" == "$image_repo" || "$image_repo" != */* ]]; then
    echo "error: TEST_IMAGE 必须写成 <registry>/<repo>:<tag> 才能推送: $TEST_IMAGE" >&2
    exit 1
  fi
  repo_path="${image_repo#*/}"
  manifest_url="https://$registry_host/v2/$repo_path/manifests/$image_tag"
  accept="Accept: application/vnd.docker.distribution.manifest.v2+json"
  if curl -skf --max-time 10 -H "$accept" -o /dev/null "$manifest_url" 2>/dev/null; then
    echo "registry 已有该镜像，跳过: $TEST_IMAGE"
  else
    echo "registry 缺少该镜像，从包内导入: $image_archive"
    if [[ "$dry_run" == "1" ]]; then
      echo "dry-run: sudo docker load -i $image_archive"
      echo "dry-run: sudo docker tag <archive 内的引用> $TEST_IMAGE"
      echo "dry-run: sudo docker push $TEST_IMAGE"
    else
      # The archive's own RepoTags are not reliable: an image saved as
      # `taa-env:slim-v2` loads without the registry prefix, while the Pod asks
      # for `172.16.10.178:31313/taa-env:slim-v2`. docker load reports the
      # reference it actually restored, and the tag is added on top of that so
      # the push lands under the name CDH will request.
      if ! load_out="$(sudo docker load -i "$image_archive" 2>&1)"; then
        printf '%s\n' "$load_out" >&2
        echo "error: 导入镜像归档失败: $image_archive" >&2
        exit 1
      fi
      printf '%s\n' "$load_out"
      # An archive can carry several tags. Prefer one whose repository matches
      # the Pod's, so a multi-image archive still resolves to the intended
      # image; fall back to the first when none matches (a differently-named
      # build).
      loaded_refs="$(sed -n 's/^Loaded image: //p' <<<"$load_out")"
      loaded_ref=""
      while IFS= read -r ref; do
        [[ -n "$ref" ]] || continue
        if [[ "${ref%%:*}" == *"$repo_path" ]]; then loaded_ref="$ref"; break; fi
        [[ -n "$loaded_ref" ]] || loaded_ref="$ref"
      done <<<"$loaded_refs"
      if [[ -z "$loaded_ref" ]]; then
        echo "error: 无法从 docker load 输出判断镜像引用，归档可能不含 RepoTags" >&2
        echo "hint: 归档需由 docker save 生成，且带 RepoTags" >&2
        exit 1
      fi
      if ! sudo docker tag "$loaded_ref" "$TEST_IMAGE"; then
        echo "error: 无法把 $loaded_ref 标记为 $TEST_IMAGE" >&2
        exit 1
      fi
      if ! sudo docker push "$TEST_IMAGE"; then
        echo "error: 推送镜像到 registry 失败: $TEST_IMAGE" >&2
        echo "hint: 确认 $registry_host 可从本机推送，或手工把该归档 load 并 push 后重试" >&2
        exit 1
      fi
    fi
  fi
else
  echo "包内未携带镜像归档，要求 registry 已存在: $TEST_IMAGE"
fi

echo
echo "== 5. 创建 RuntimeClass 与测试 Pod =="
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
echo "== 6. 等待测试 Pod Ready =="
if ! kubectl wait --for=condition=Ready "pod/$TEST_POD_NAME" --timeout=180s; then
  echo "error: test Pod did not become Ready within 180s; status and events follow" >&2
  kubectl get pod "$TEST_POD_NAME" -o wide >&2 || true
  kubectl describe pod "$TEST_POD_NAME" 2>&1 | sed -n '/Events:/,$p' >&2 || true
  exit 1
fi
kubectl get pod "$TEST_POD_NAME" -o wide

echo
echo "== 7. 校验 QEMU 使用了本包的 initrd =="
if ps -eo args= | grep -F "qemu" | grep -F "$REMOTE_BUNDLE_DIR/initramfs.img" | grep -v grep >/dev/null; then
  echo "verified QEMU is using: $REMOTE_BUNDLE_DIR/initramfs.img"
else
  echo "error: Pod is ready, but no QEMU command line with $REMOTE_BUNDLE_DIR/initramfs.img was found" >&2
  echo "hint: run: ps -eo args= | grep -F qemu | grep -F '$REMOTE_BUNDLE_DIR'" >&2
  exit 1
fi

echo
echo "== 8. 度量核对 =="
# The expected MEASUREMENT is recomputed here from the config that was just
# rendered onto this host. That is the only input that can differ from the
# build host: the kernel, initrd and OVMF are the package's own bytes, and the
# command line follows from the config. A difference from the running VM then
# means identity.txt changed or the host's Kata drifted, not that the package
# is stale.
expected_hex=""
expected_cmdline=""
smp_args=()
[[ -n "${MEASURE_SMP:-}" ]] && smp_args=(--smp "$MEASURE_SMP")
if expected_cmdline="$(python3 "$pkg_dir/measure.py" cmdline \
    --config "$package_kata_config" --section "$kata_section" \
    ${smp_args[@]+"${smp_args[@]}"} 2>/dev/null)"; then
  expected_file="$(mktemp /tmp/taa-expected.XXXXXX.txt)"
  printf '%s\n' "$expected_cmdline" > "$expected_file"
  if expected_out="$(python3 "$pkg_dir/measure.py" digest \
    --ovmf "$REMOTE_BUNDLE_DIR/OVMF.fd" \
    --kernel "$REMOTE_BUNDLE_DIR/vmlinuz" \
    --initrd "$REMOTE_BUNDLE_DIR/initramfs.img" \
    --cmdline "$expected_file" 2>/dev/null)"; then
    expected_hex="$(sed -n 's/^hex=//p' <<<"$expected_out")"
  fi
  rm -f "$expected_file"
fi

if [[ -z "$expected_hex" ]]; then
  echo "warning: 无法按当前配置重算预期 MEASUREMENT，跳过核对" >&2
else
  echo "预期 MEASUREMENT (hex):    $expected_hex"
  echo "预期 cmdline: $expected_cmdline"
  qpid="$(ps -eo pid=,args= | grep -F qemu | grep -F "$REMOTE_BUNDLE_DIR/initramfs.img" |
    grep -v grep | awk '{print $1}' | head -n 1 || true)"
  append_file="$(mktemp /tmp/taa-append.XXXXXX.txt)"
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
      printf '%s\n' "$append_value" > "$append_file"
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
      elif [[ "$actual_hex" == "$expected_hex" ]]; then
        echo "实际 MEASUREMENT (hex):    $actual_hex"
        echo "实际 MEASUREMENT (base64): $actual_b64"
        echo "与实际启动的 VM 一致（预期值按当前配置重算）"
      else
        echo "实际 MEASUREMENT (hex):    $actual_hex"
        echo "实际 MEASUREMENT (base64): $actual_b64"
        echo "warning: 实际度量与预期不一致（预期值按当前配置重算）" >&2
        echo "  预期 hex: $expected_hex" >&2
        echo "  实际 cmdline: $(cat "$append_file")" >&2
        echo "hint: 以实际 cmdline 的重算结果为准；若宿主升级了 Kata，请重新 render" >&2
      fi
    fi
  fi
fi

echo
echo "安装完成。使用方创建 Pod 时指定 runtimeClassName: $RUNTIME_HANDLER"
echo
echo "注意: runtime handler 的 ConfigPath 指向本交付包: $REMOTE_KATA_CONFIG"
echo "      删除或替换该目录前先移除 handler，否则下次拉起该 runtime 的 Pod 会失败。"
