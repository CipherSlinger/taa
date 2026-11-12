#!/usr/bin/env bash
# Install the TAA-in-initrd delivery package on a Kata CSV2 host.
#
# The package is produced by `build-initrd.sh render` (or by `launch`, which
# renders the same files first). This script installs the runtime handler as a
# TAA-owned containerd drop-in, pushes the Pod image into its registry and
# creates the RuntimeClass. Creating and deleting the test Pod is a separate
# step under test/, so an install never starts a guest.
#
# The handler is never merged into /etc/containerd/config.toml or into another
# drop-in. Every TAA package shares one snapshot, ../zz-taa-runtimes.toml beside
# the package directories (/root/taa-images). The first install seeds it from
# the last file under /etc/containerd/conf.d that defines runtimes (ignoring
# TAA's own drop-in), adds this package's handler and copies it to
# /etc/containerd/conf.d/, overwriting the previous copy. Later installs of any
# package reuse it, so one package's handler cannot hide another's, and
# uninstall.sh can take the handler out again. containerd replaces the whole
# CRI plugin tree with the last imported file that defines it, so the file must
# carry every handler; one holding only the new handler would silently delete
# all the others.
#
# Every setting is derived from the package itself -- the runtime handler and
# its ConfigPath from config/containerd-runtime-handler.toml, the boot assets
# from kata-config.toml. render.py package-info reads both and refuses a
# package whose absolute paths do not name its own files, so a moved or
# half-assembled directory fails before anything is touched.
#
# The deployment identity (platform address, docker id, public key, LLM
# endpoint, ...) is not part of this installation: it lives in the
# kernel_params annotation of the Pod that runs. To change it, edit
# test/test-pod.yaml and re-run test/create-test-pod.sh; consumer Pods must
# carry the same annotation themselves. No reinstall, no rebuild and no
# re-upload: the initrd's bytes, and with them its measurement basis, stay as
# they are; only the measured kernel command line changes.
#
# Usage: sudo bash install.sh [--dry-run]
#
# Environment overrides:
#   CONTAINERD_CONFIG    containerd main config whose imports are read
#                        (default /etc/containerd/config.toml)
#   CONTAINERD_CONF_DIR  directory the drop-in is copied into
#                        (default /etc/containerd/conf.d)
#   TAA_RUNTIMES_FILE    shared snapshot this package reads and rewrites
#                        (default ../zz-taa-runtimes.toml beside the package)
#   RESTART_KUBELET      1 also restarts kubelet after containerd (default 0)
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
CONTAINERD_CONF_DIR="${CONTAINERD_CONF_DIR:-/etc/containerd/conf.d}"
# Sort after every other drop-in: 99-nvidia.toml and the numeric prefixes all
# sort before a leading letter. The install verifies the ordering outcome rather
# than trusting the name alone.
CONTAINERD_DROPIN_NAME="zz-taa-runtimes.toml"

tmp_dropin=""
tmp_stage=""
dropin_backup=""
cleanup() {
  if [[ -n "$tmp_dropin" ]]; then rm -f "$tmp_dropin"; fi
  if [[ -n "$tmp_stage" ]]; then rm -f "$tmp_stage"; fi
  if [[ -n "$dropin_backup" ]]; then sudo rm -f "$dropin_backup" || true; fi
  return 0
}
trap cleanup EXIT

# Handler names in a `containerd config dump`. Tables are indented and the
# handler name is quoted only when it is not a bare TOML key; both spellings are
# accepted, and the child options table is dropped.
handlers_of_dump() {
  sed -n \
    's/^[[:space:]]*\[plugins\."io\.containerd\.grpc\.v1\.cri"\.containerd\.runtimes\.\([^]]*\)\][[:space:]]*$/\1/p' |
    { grep -v '\.options$' || true; } |
    sed 's/^"//; s/"$//' |
    sort -u
}

# The effective options table of one handler in a dump (stdin).
handler_options_of() {
  awk -v pre='[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.' -v handler="$1" '
    {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      if (line ~ /^\[/) {
        in_table = (line == pre handler ".options]" ||
                    line == pre "\"" handler "\".options]")
        next
      }
      if (in_table) print line
    }'
}

# Handlers present in the first set but missing from the second.
lost_handlers() {
  comm -23 <(printf '%s\n' "$1" | sed '/^$/d') <(printf '%s\n' "$2" | sed '/^$/d')
}

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
echo "== 2. Kata 配置 =="
package_kata_config="$pkg_dir/$PACKAGE_KATA_CONFIG"
if [[ ! -f "$package_kata_config" ]]; then
  echo "error: 包内 Kata 配置缺失: $package_kata_config" >&2
  exit 1
fi

# The handler's ConfigPath points at the packaged copy (package_info verified
# it), so there is nothing to install under /etc: the package is the host's only
# copy, and install(1) would refuse anyway ("are the same file").
echo "Kata 配置即交付包内文件，无需安装: $REMOTE_KATA_CONFIG"
echo "Kata guest assets in $REMOTE_KATA_CONFIG:"
grep -nE '^[[:space:]]*(kernel|initrd|firmware|kernel_params)[[:space:]]*=' "$package_kata_config"

echo
echo "== 3. 安装 containerd runtime handler（TAA 自有 drop-in）=="
dropin_dest="$CONTAINERD_CONF_DIR/$CONTAINERD_DROPIN_NAME"
# One snapshot shared by every TAA package on the host, kept beside the package
# directories (/root/taa-images) instead of inside one package. A per-package
# copy went stale as soon as another role installed its own handler, so each
# script reads and rewrites this one file.
shared_dropin="${TAA_RUNTIMES_FILE:-$(dirname "$pkg_dir")/$CONTAINERD_DROPIN_NAME}"

# The drop-in only takes effect through an import. Refuse early rather than
# install a file nothing reads.
if ! grep -qF "$CONTAINERD_CONF_DIR/*.toml" "$CONTAINERD_CONFIG" &&
   ! grep -qF "$dropin_dest" "$CONTAINERD_CONFIG"; then
  echo "error: $CONTAINERD_CONFIG 的 imports 没有包含 $CONTAINERD_CONF_DIR/*.toml" >&2
  echo "       drop-in 不会被 containerd 读取，安装会静默失效" >&2
  exit 1
fi

# The handler set in effect today. install.sh must not remove any of it; the
# only permitted change is adding or refreshing this package's handler.
if ! before_dump="$(sudo containerd --config "$CONTAINERD_CONFIG" config dump)"; then
  echo "error: 当前 containerd 配置无法解析，未改动宿主" >&2
  exit 1
fi
before_handlers="$(handlers_of_dump <<<"$before_dump")"
echo "当前生效 handler 数: $(sed '/^$/d' <<<"$before_handlers" | wc -l)"

tmp_dropin="$(mktemp /tmp/containerd-dropin.taa.XXXXXX.toml)"
tmp_stage="$(mktemp /tmp/containerd-stage.taa.XXXXXX.toml)"
carry_args=()
if [[ -f "$dropin_dest" ]]; then
  carry_args=(--carry "$dropin_dest")
fi
# First install: seed from the file that currently wins under conf.d, ignoring
# TAA's own drop-in (deriving from it would freeze the host at the first
# install). Reinstall: reuse the shared file, which is the snapshot all TAA
# packages read and rewrite. Either way, carry over handlers other TAA packages
# installed, because two packages seeded from the same host file would
# otherwise overwrite each other.
base_args=()
if [[ -f "$shared_dropin" ]]; then
  base_args=(--base "$shared_dropin")
fi
# A drop-in holding only our handler would replace the whole CRI plugin tree and
# delete every other runtime (containerd merges the plugins map key by key, and
# the CRI tree is one value). So the generator starts from a full snapshot and
# appends ours.
if ! python3 "$pkg_dir/render.py" containerd-dropin \
  --config "$CONTAINERD_CONFIG" \
  --exclude-prefix zz-taa \
  "${base_args[@]+"${base_args[@]}"}" \
  "${carry_args[@]+"${carry_args[@]}"}" \
  --handler "$RUNTIME_HANDLER" \
  --runtime-type "$RUNTIME_TYPE" \
  --runtime-path "$RUNTIME_PATH" \
  --snapshotter "$SNAPSHOTTER" \
  --kata-config "$REMOTE_KATA_CONFIG" \
  --out "$tmp_dropin"; then
  echo "error: 生成 containerd drop-in 失败，未改动宿主" >&2
  exit 1
fi

# Stage the prospective configuration: same imports, plus this drop-in last.
# `config dump` then resolves exactly what containerd would load on restart,
# while /etc is still untouched.
if ! python3 "$pkg_dir/render.py" containerd-stage \
  --config "$CONTAINERD_CONFIG" --extra "$tmp_dropin" --out "$tmp_stage"; then
  echo "error: 生成 containerd 预检配置失败，未改动宿主" >&2
  exit 1
fi
if ! stage_dump="$(sudo containerd --config "$tmp_stage" config dump)"; then
  echo "error: 生成的 drop-in 无法被 containerd 解析，未改动宿主" >&2
  exit 1
fi
stage_handlers="$(handlers_of_dump <<<"$stage_dump")"
if ! grep -qxF "$RUNTIME_HANDLER" <<<"$stage_handlers"; then
  echo "error: 预检配置里没有出现 $RUNTIME_HANDLER" >&2
  exit 1
fi
lost="$(lost_handlers "$before_handlers" "$stage_handlers")"
if [[ -n "$lost" ]]; then
  echo "error: 新 drop-in 会丢掉已生效的 handler:" >&2
  printf '%s\n' "$lost" | sed 's/^/         /' >&2
  echo "hint: drop-in 必须是宿主当前 runtimes 表的完整快照，而不是只有本包的 handler" >&2
  exit 1
fi
stage_options="$(handler_options_of "$RUNTIME_HANDLER" <<<"$stage_dump")"
if ! grep -qxF "ConfigPath = \"$REMOTE_KATA_CONFIG\"" <<<"$stage_options"; then
  echo "error: 预检配置里，$RUNTIME_HANDLER 的 ConfigPath 不是 $REMOTE_KATA_CONFIG" >&2
  echo "       生效的 options 表:" >&2
  printf '%s\n' "${stage_options:-(缺失)}" | sed 's/^/         /' >&2
  exit 1
fi
echo "预检通过: $RUNTIME_HANDLER -> $REMOTE_KATA_CONFIG（未丢 handler）"

if [[ "$dry_run" == "1" ]]; then
  echo "dry-run: 将写入共享 drop-in $shared_dropin"
  echo "dry-run: sudo install -o root -g root -m 0644 $tmp_dropin $dropin_dest"
  echo "dry-run: sudo systemctl restart containerd"
else
  # Keep the shared snapshot beside the packages, so any role can inspect it
  # and the next install of any package starts from the same table.
  sudo install -o root -g root -m 0644 "$tmp_dropin" "$shared_dropin"
  echo "已写入共享 drop-in: $shared_dropin"

  if [[ -f "$dropin_dest" ]] && sudo cmp -s "$tmp_dropin" "$dropin_dest"; then
    echo "drop-in 未变化，跳过重启: $dropin_dest"
  else
    if [[ -f "$dropin_dest" ]]; then
      dropin_backup="$(mktemp /tmp/containerd-dropin.backup.XXXXXX.toml)"
      sudo cp -a "$dropin_dest" "$dropin_backup"
    fi
    rollback_dropin() {
      if [[ -n "$dropin_backup" && -f "$dropin_backup" ]]; then
        sudo install -o root -g root -m 0644 "$dropin_backup" "$dropin_dest"
      else
        sudo rm -f "$dropin_dest"
      fi
    }
    sudo install -o root -g root -m 0644 "$tmp_dropin" "$dropin_dest"
    echo "已安装 drop-in: $dropin_dest"

    # The authoritative check: the real config, resolved in place.
    if ! after_dump="$(sudo containerd --config "$CONTAINERD_CONFIG" config dump)"; then
      echo "error: 安装 drop-in 后 containerd 配置无法解析，回滚" >&2
      rollback_dropin
      exit 1
    fi
    after_handlers="$(handlers_of_dump <<<"$after_dump")"
    lost="$(lost_handlers "$before_handlers" "$after_handlers")"
    if [[ -n "$lost" ]] ||
       ! grep -qxF "$RUNTIME_HANDLER" <<<"$after_handlers" ||
       ! grep -qxF "ConfigPath = \"$REMOTE_KATA_CONFIG\"" \
         <<<"$(handler_options_of "$RUNTIME_HANDLER" <<<"$after_dump")"; then
      echo "error: 生效配置校验失败，回滚 drop-in" >&2
      if [[ -n "$lost" ]]; then
        printf '%s\n' "$lost" | sed 's/^/         丢失: /' >&2
      fi
      rollback_dropin
      exit 1
    fi
    echo "生效配置校验通过: $RUNTIME_HANDLER -> $REMOTE_KATA_CONFIG"

    echo "重启 containerd"
    if ! sudo systemctl restart containerd || ! sudo systemctl is-active --quiet containerd; then
      sudo journalctl -u containerd -n 50 --no-pager >&2 || true
      echo "error: containerd 重启失败，回滚 drop-in" >&2
      rollback_dropin
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
    sudo rm -f "$dropin_backup"
    dropin_backup=""
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
if [[ -n "${TEST_POD_KERNEL_PARAMS:-}" ]]; then
  echo "并且必须带上与测试 Pod 相同的身份注解（部署身份是按 Pod 生效的）："
  printf '  io.katacontainers.config.hypervisor.kernel_params: "%s"\n' \
    "$TEST_POD_KERNEL_PARAMS"
fi
echo
echo "注意: runtime handler 的 ConfigPath 指向本交付包: $REMOTE_KATA_CONFIG"
echo "      删除或替换该目录前先移除 handler，否则下次拉起该 runtime 的 Pod 会失败。"
echo "      handler 由 $dropin_dest 提供（完整快照，含宿主原有 handler）；"
echo "      不要直接编辑，重跑本脚本会覆盖它。"
