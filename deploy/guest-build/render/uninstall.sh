#!/usr/bin/env bash
# Uninstall the containerd runtime handler installed by install.sh.
#
# This is the reverse of install.sh's containerd step. The installed drop-in
# /etc/containerd/conf.d/zz-taa-runtimes.toml is the source of truth: it is the
# full snapshot every TAA package contributed to, so removing this package's
# handler from it cannot delete another package's handler. The result is written
# back to the shared file (../zz-taa-runtimes.toml beside the package
# directories, /root/taa-images by default) and over the installed file. When no
# TAA-owned handler remains, the drop-in is removed from /etc/containerd/conf.d
# so containerd falls back to the host's own file.
#
# containerd reads imports only at startup, so the daemon is restarted after a
# change, exactly as install.sh does. RuntimeClass and the Pod image are not
# touched: they are separate Kubernetes/registry resources, and an uninstall
# that silently deleted them would be wider than the containerd configuration
# this script owns.
#
# Usage: sudo bash uninstall.sh [--dry-run]
#
# Environment overrides:
#   CONTAINERD_CONFIG    containerd main config whose imports are read
#                        (default /etc/containerd/config.toml)
#   CONTAINERD_CONF_DIR  directory the drop-in was installed into
#                        (default /etc/containerd/conf.d)
#   TAA_RUNTIMES_FILE    shared snapshot this package reads and rewrites
#                        (default ../zz-taa-runtimes.toml beside the package)
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
CONTAINERD_DROPIN_NAME="zz-taa-runtimes.toml"
# Handler names this repository owns. The drop-in is deleted only when none of
# them remains, so uninstalling one package never removes another package's
# handler.
TAA_HANDLER_RE='^kata-qemu-(nondcu|dcu)-csv2-taa-'

tmp_remove=""
dropin_backup=""
cleanup() {
  if [[ -n "$tmp_remove" ]]; then rm -f "$tmp_remove"; fi
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

echo "== 卸载 containerd runtime handler =="

for cmd in sudo python3 containerd grep cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: $cmd is not installed or not in PATH" >&2
    exit 1
  fi
done

if ! pkg_settings="$(python3 "$pkg_dir/render.py" package-info --dir "$pkg_dir")"; then
  echo "error: 交付包自校验失败，未改动宿主" >&2
  exit 1
fi
# package-info quotes every value, so eval is safe.
eval "$pkg_settings"

dropin_dest="$CONTAINERD_CONF_DIR/$CONTAINERD_DROPIN_NAME"
# The snapshot shared by every TAA package, kept beside the package directories
# (/root/taa-images). install.sh seeds and rewrites this same file.
shared_dropin="${TAA_RUNTIMES_FILE:-$(dirname "$pkg_dir")/$CONTAINERD_DROPIN_NAME}"
echo "runtime handler: $RUNTIME_HANDLER"

if [[ "$(id -u)" -ne 0 ]] && ! sudo -n true 2>/dev/null; then
  echo "error: this account needs passwordless sudo (sudo -n true failed)" >&2
  echo "hint: run as root, or add a NOPASSWD sudoers entry" >&2
  exit 1
fi

if [[ ! -f "$CONTAINERD_CONFIG" ]]; then
  echo "error: containerd config not found: $CONTAINERD_CONFIG" >&2
  exit 1
fi
if ! grep -qF "$CONTAINERD_CONF_DIR/*.toml" "$CONTAINERD_CONFIG" &&
   ! grep -qF "$dropin_dest" "$CONTAINERD_CONFIG"; then
  echo "error: $CONTAINERD_CONFIG 的 imports 没有包含 $CONTAINERD_CONF_DIR/*.toml" >&2
  echo "       TAA 的 drop-in 本来就不会被 containerd 读取，无需卸载" >&2
  exit 1
fi

if [[ ! -f "$dropin_dest" ]]; then
  # Nothing is installed on this host. Still make the shared snapshot
  # consistent, so a later install does not resurrect the handler from it.
  if [[ ! -f "$shared_dropin" ]]; then
    echo "未安装该 handler，宿主与共享 drop-in 都不存在，无需操作"
    exit 0
  fi
  tmp_remove="$(mktemp /tmp/containerd-remove.taa.XXXXXX.toml)"
  python3 "$pkg_dir/render.py" containerd-remove \
    --file "$shared_dropin" --handler "$RUNTIME_HANDLER" --out "$tmp_remove"
  if ! cmp -s "$tmp_remove" "$shared_dropin"; then
    run sudo install -o root -g root -m 0644 "$tmp_remove" "$shared_dropin"
    echo "宿主未安装该 drop-in；已从共享 drop-in 移除: $shared_dropin"
  else
    echo "宿主未安装该 drop-in；共享 drop-in 中也没有 $RUNTIME_HANDLER，无需操作"
  fi
  exit 0
fi

# The installed drop-in is the superset, so remove from it rather than from the
# shared snapshot: the shared file may predate another package's install.
tmp_remove="$(mktemp /tmp/containerd-remove.taa.XXXXXX.toml)"
if ! python3 "$pkg_dir/render.py" containerd-remove \
  --file "$dropin_dest" --handler "$RUNTIME_HANDLER" --out "$tmp_remove"; then
  echo "error: 从 $dropin_dest 删除 $RUNTIME_HANDLER 失败，未改动宿主" >&2
  exit 1
fi

remaining_taa="$(python3 "$pkg_dir/render.py" containerd-handlers --file "$tmp_remove" |
  { grep -E "$TAA_HANDLER_RE" || true; } | sort -u)"

if ! before_dump="$(sudo containerd --config "$CONTAINERD_CONFIG" config dump)"; then
  echo "error: 当前 containerd 配置无法解析，未改动宿主" >&2
  exit 1
fi
before_handlers="$(handlers_of_dump <<<"$before_dump")"
expected_handlers="$(printf '%s\n' "$before_handlers" | { grep -vxF "$RUNTIME_HANDLER" || true; })"

if [[ -n "$remaining_taa" ]]; then
  echo "仍保留其它 TAA handler:"
  printf '%s\n' "$remaining_taa" | sed 's/^/  /'
  action="install"
else
  echo "该 drop-in 已不含任何 TAA handler，将从 $CONTAINERD_CONF_DIR 删除"
  action="delete"
fi

if [[ "$dry_run" == "1" ]]; then
  echo "dry-run: 将写入共享 drop-in $shared_dropin"
  if [[ "$action" == "install" ]]; then
    echo "dry-run: sudo install -o root -g root -m 0644 $tmp_remove $dropin_dest"
  else
    echo "dry-run: sudo rm -f $dropin_dest"
  fi
  echo "dry-run: sudo systemctl restart containerd"
  exit 0
fi

sudo install -o root -g root -m 0644 "$tmp_remove" "$shared_dropin"
echo "已写入共享 drop-in: $shared_dropin"

dropin_backup="$(mktemp /tmp/containerd-dropin.backup.XXXXXX.toml)"
sudo cp -a "$dropin_dest" "$dropin_backup"
rollback_dropin() {
  sudo install -o root -g root -m 0644 "$dropin_backup" "$dropin_dest"
}

if cmp -s "$tmp_remove" "$dropin_dest"; then
  echo "drop-in 未变化，跳过重启: $dropin_dest"
  exit 0
fi

if [[ "$action" == "install" ]]; then
  sudo install -o root -g root -m 0644 "$tmp_remove" "$dropin_dest"
  echo "已更新 drop-in: $dropin_dest"
else
  sudo rm -f "$dropin_dest"
  echo "已删除 drop-in: $dropin_dest"
fi

# The authoritative check: resolve the real configuration in place.
if ! after_dump="$(sudo containerd --config "$CONTAINERD_CONFIG" config dump)"; then
  echo "error: 卸载后 containerd 配置无法解析，回滚" >&2
  rollback_dropin
  exit 1
fi
after_handlers="$(handlers_of_dump <<<"$after_dump")"
lost="$(lost_handlers "$expected_handlers" "$after_handlers")"
added="$(lost_handlers "$after_handlers" "$expected_handlers")"
if [[ -n "$lost" || -n "$added" ]]; then
  echo "error: 生效 handler 与预期不一致，回滚 drop-in" >&2
  if [[ -n "$lost" ]]; then
    printf '%s\n' "$lost" | sed 's/^/         丢失: /' >&2
  fi
  if [[ -n "$added" ]]; then
    printf '%s\n' "$added" | sed 's/^/         多出: /' >&2
  fi
  rollback_dropin
  exit 1
fi
echo "生效配置校验通过: $RUNTIME_HANDLER 已移除，其它 handler 未变"

echo "重启 containerd"
if ! sudo systemctl restart containerd || ! sudo systemctl is-active --quiet containerd; then
  sudo journalctl -u containerd -n 50 --no-pager >&2 || true
  echo "error: containerd 重启失败，回滚 drop-in" >&2
  rollback_dropin
  sudo systemctl restart containerd || true
  exit 1
fi
