#!/usr/bin/env bash
# Install the TAA-in-initrd delivery package on a Kata CSV2 host.
#
# The package is produced by `build-initrd.sh render` (or by `launch`, which
# renders the same files first). This script re-renders the Kata config from the
# editable `config/env.txt`, merges the containerd runtime handler, pushes the
# Pod image into its registry and creates the RuntimeClass. Creating and
# deleting the test Pod is a separate step under test/, so an install no longer
# starts a guest.
#
# Every setting is derived from the package itself -- the runtime handler and
# its ConfigPath from config/containerd-runtime-handler.toml, the boot assets
# from config/kata-config.toml. render.py package-info reads both and refuses a
# package whose absolute paths do not name its own files, so a moved or
# half-assembled directory fails before anything is touched.
#
# To change the deployment identity (platform address, docker id, public key,
# LLM endpoint, ...) edit config/env.txt and re-run this script, then re-run
# test/create-test-pod.sh: the identity reaches a guest only through a newly
# created Pod. No rebuild and no re-upload: the initrd's bytes, and with them
# its measurement basis, stay as they are; only the measured kernel command
# line changes.
#
# Usage: sudo bash install.sh [--dry-run]
#
# Environment overrides:
#   CONTAINERD_CONFIG   containerd config to merge the handler into
#                       (default /etc/containerd/config.toml)
#   RESTART_KUBELET     1 also restarts kubelet after containerd (default 0)
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
cleanup() {
  if [[ -n "$tmp_kata_config" ]]; then rm -f "$tmp_kata_config"; fi
  if [[ -n "$tmp_containerd" ]]; then rm -f "$tmp_containerd"; fi
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

for cmd in kubectl sudo python3 containerd grep sha256sum cmp; do
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
echo "== 2. Kata 配置（按 config/env.txt 重新渲染）=="
package_kata_config="$pkg_dir/$PACKAGE_KATA_CONFIG"
if [[ ! -f "$package_kata_config" ]]; then
  echo "error: 包内 Kata 配置缺失: $package_kata_config" >&2
  exit 1
fi

if [[ -f "$identity_file" ]]; then
  echo "部署身份 (config/env.txt):"
  grep -vE '^[[:space:]]*(#|$)' "$identity_file" | sed 's/^/  /'
  tmp_kata_config="$(mktemp /tmp/kata-config.taa.XXXXXX.toml)"
  if ! python3 "$pkg_dir/render.py" kata-config \
    --template "$package_kata_config" \
    --section "$kata_section" \
    --bundle-dir "$REMOTE_BUNDLE_DIR" \
    --param-file "$identity_file" \
    --out "$tmp_kata_config"; then
    echo "error: 按 config/env.txt 渲染 Kata 配置失败，未改动宿主配置" >&2
    exit 1
  fi
  if cmp -s "$tmp_kata_config" "$package_kata_config"; then
    echo "与交付时一致，Kata 配置无需更新"
  else
    echo "身份已修改，更新 $PACKAGE_KATA_CONFIG"
    run sudo install -o root -g root -m 0644 "$tmp_kata_config" "$package_kata_config"
  fi
else
  echo "warning: 包内没有 config/env.txt，沿用交付时的 Kata 配置" >&2
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

# `config dump` is not only a syntax check: it renders the configuration
# containerd will actually use, `imports` included. A drop-in that defines the
# same handler wins over the file the installer just wrote, and the override is
# silent -- containerd starts happily and the Pod then boots the drop-in's
# ConfigPath, or fails on a directory that no longer exists. Checking the merged
# file alone cannot see that, so the effective handler entry is checked too.
if ! effective_dump="$(sudo containerd --config "$tmp_containerd" config dump)"; then
  echo "error: 生成的 containerd 配置无效，未改动宿主配置" >&2
  exit 1
fi

# The dump prints the handler table bare when the name is a valid TOML key and
# quoted when it is not; both spellings are accepted here.
effective_options="$(printf '%s\n' "$effective_dump" | awk \
  -v pre='[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.' \
  -v handler="$RUNTIME_HANDLER" '
  {
    line = $0
    sub(/^[[:space:]]+/, "", line)
    if (line ~ /^\[/) {
      in_table = (line == pre handler ".options]" ||
                  line == pre "\"" handler "\".options]")
      next
    }
    if (in_table) print line
  }')"
if ! grep -qxF "ConfigPath = \"$REMOTE_KATA_CONFIG\"" <<<"$effective_options"; then
  echo "error: 生效的 containerd 配置里，$RUNTIME_HANDLER 的 ConfigPath 不是 $REMOTE_KATA_CONFIG" >&2
  echo "       主配置: $CONTAINERD_CONFIG" >&2
  echo "       生效的 options 表:" >&2
  printf '%s\n' "${effective_options:-(缺失)}" | sed 's/^/         /' >&2
  echo "hint: 多半是 imports 里的 drop-in 定义了同名 handler 并覆盖了主配置;" >&2
  echo "      检查 imports 列出的文件（例如 /etc/containerd/conf.d/*.toml）" >&2
  exit 1
fi
echo "生效配置校验通过: $RUNTIME_HANDLER -> $REMOTE_KATA_CONFIG"

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
echo "== 5. 创建 RuntimeClass =="
# The RuntimeClass is what lets a Pod select this handler by name; every Pod
# using the runtime needs it, so it is installed here and not with the test Pod.
# `apply` is idempotent for a same-named object, but `handler` is immutable: a
# renamed handler needs the old RuntimeClass deleted first.
run kubectl apply -f "$pkg_dir/$PACKAGE_RUNTIMECLASS"

if [[ "$dry_run" == "1" ]]; then
  echo "dry-run 结束：以上内容尚未安装"
  exit 0
fi

echo
echo "安装完成。"
echo "测试 Pod 不随安装创建，需要时在宿主机上执行："
echo "  sudo bash $pkg_dir/test/create-test-pod.sh   # 创建、等待 Ready，核对 initrd 与 MEASUREMENT"
echo "  sudo bash $pkg_dir/test/delete-test-pod.sh   # 删除测试 Pod"
echo
echo "使用方创建 Pod 时指定 runtimeClassName: $RUNTIME_HANDLER"
echo
echo "注意: runtime handler 的 ConfigPath 指向本交付包: $REMOTE_KATA_CONFIG"
echo "      删除或替换该目录前先移除 handler，否则下次拉起该 runtime 的 Pod 会失败。"
