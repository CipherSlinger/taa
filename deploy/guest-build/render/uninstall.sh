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
taa_py=""
cleanup() {
  if [[ -n "$taa_py" ]]; then rm -f "$taa_py"; fi
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

# The package's own reading of itself. Kept inline rather than shipped as a
# separate file: it is the only Python this script needs, and a package with
# one fewer moving part is one fewer thing that can go missing in transit.
taa_py="$(mktemp /tmp/taa-pkg.XXXXXX.py)"
cat > "$taa_py" <<'TAA_PY'
# Read the package and take this package's handler back out of a drop-in. The
# delivery package ships no renderer, so the TOML handling this script needs is
# carried here, in one block, so what runs on the host is what was reviewed.

import json, re, shlex, sys
from pathlib import Path


CRI = "io.containerd.grpc.v1.cri"
RUNTIMES = ("plugins", CRI, "containerd", "runtimes")
KERNEL_PARAMS_ANNOTATION = "io.katacontainers.config.hypervisor.kernel_params"
IMAGE_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar")


def split_table_path(src):
    """Split a TOML table path on dots, respecting quoted segments."""
    parts, buf, in_quote, escape = [], [], False, False
    for ch in src:
        if in_quote:
            if escape:
                buf.append(ch)
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_quote = False
            else:
                buf.append(ch)
        else:
            if ch == '"':
                in_quote = True
            elif ch == ".":
                parts.append("".join(buf).strip())
                buf = []
            else:
                buf.append(ch)
    parts.append("".join(buf).strip())
    return parts


def table_path(line):
    stripped = line.strip()
    if stripped.startswith("[["):
        return None
    if stripped.startswith("[") and stripped.endswith("]"):
        return split_table_path(stripped[1:-1].strip())
    return None


def toml_value(raw):
    raw = raw.strip()
    if raw.startswith('"'):
        return json.loads(raw)
    return raw


def collect_settings(path):
    """Map table path -> {key: value} for simple `key = value` lines.

    Only the subset the package writes is understood: one assignment per line,
    quoted or bare values, no inline tables or arrays of interest. Stdlib only,
    and no tomllib -- the installer runs on the target host, whose python3 may
    predate 3.11.
    """
    settings = {}
    current = ()
    for line in Path(path).read_text().splitlines():
        parts = table_path(line)
        if parts is not None:
            current = tuple(parts)
            settings.setdefault(current, {})
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        settings.setdefault(current, {})[key.strip()] = toml_value(value)
    return settings


def image_tar_name(image, suffix=".tar"):
    """Return the filename the packaged copy of `image` is stored under.

    The registry prefix is dropped, so `172.16.10.178:31313/taa-env:slim-v2`
    becomes `taa-env_slim-v2.tar`. The host address only made the archive look
    bound to the build host's registry, while the full reference is already in
    the Pod manifest; the repository and tag are what a person searches for by
    hand. Only characters that cannot appear in a filename are rewritten.

    `suffix` follows the archive as supplied, so a gzipped `docker save` output
    keeps its `.tar.gz` and a reader is not told it holds a plain tar. docker
    load sniffs the format either way; the name is for people.
    """
    name = image.split("/", 1)[-1]
    return re.sub(r"[/:]", "_", name) + suffix


def package_info(pkg_dir):
    """Derive the installer's settings from the package itself.

    The package no longer carries a parameter sheet: everything install.sh needs
    is already written into the files it ships, and the paths follow from where
    the package sits. This is also the check that a package was not moved after
    rendering -- the Kata config names absolute bundle paths, so a directory that
    does not contain them is not the directory the config was rendered for.

    Emits shell-safe `KEY=value` lines; install.sh evals them.
    """
    pkg = Path(pkg_dir).resolve()
    fragment = pkg / "config" / "containerd-runtime-handler.toml"
    kata_config = pkg / "kata-config.toml"
    pod_file = pkg / "test" / "test-pod.yaml"
    runtimeclass_file = pkg / "k8s" / "runtimeclass.yaml"
    bundle = pkg / "bundle"

    for path in (fragment, kata_config, pod_file, runtimeclass_file):
        if not path.is_file():
            raise SystemExit(f"package is incomplete, missing {path}")

    settings = collect_settings(fragment)
    runtimes = [
        table for table in settings
        if len(table) == 5
        and table[:4] == ("plugins", "io.containerd.grpc.v1.cri", "containerd", "runtimes")
    ]
    if len(runtimes) != 1:
        raise SystemExit(
            f"{fragment}: expected exactly one runtime handler table, found {len(runtimes)}"
        )
    base = runtimes[0]
    handler = base[4]
    fields = settings[base]
    options = settings.get(base + ("options",), {})
    if not fields.get("runtime_type"):
        raise SystemExit(f"{fragment}: missing runtime_type for handler {handler}")
    if not options.get("ConfigPath"):
        raise SystemExit(f"{fragment}: missing options.ConfigPath for handler {handler}")

    # The handler has to point at this directory's own config: the package is the
    # runtime dependency, and a ConfigPath from somewhere else either means the
    # package was moved or the two files came from different renders.
    config_path = Path(options["ConfigPath"])
    if not config_path.is_absolute() or config_path.resolve() != kata_config:
        raise SystemExit(
            f"{fragment}: ConfigPath {options['ConfigPath']} does not point at {kata_config}\n"
            "hint: the package was moved after rendering, or it is incomplete"
        )

    kata = collect_settings(kata_config)
    sections = [
        table for table in kata
        if len(table) == 2 and table[0] == "hypervisor" and "kernel" in kata[table]
    ]
    if len(sections) != 1:
        raise SystemExit(
            f"{kata_config}: expected exactly one hypervisor section with kernel=, "
            f"found {len(sections)}"
        )
    section = ".".join(sections[0])
    values = kata[sections[0]]
    expected_assets = {
        "kernel": bundle / "vmlinuz",
        "initrd": bundle / "initramfs.img",
        "firmware": bundle / "OVMF.fd",
    }
    for key, expected in expected_assets.items():
        actual = Path(values.get(key, ""))
        if actual.resolve() != expected.resolve():
            raise SystemExit(
                f"{kata_config}: {key} = {values.get(key)!r} does not point at {expected}\n"
                "hint: the package was moved or assembled from different renders"
            )
        if not expected.is_file():
            raise SystemExit(
                f"package is incomplete, missing {expected}\n"
                "hint: re-render on the build host; the package ships initrd, kernel and OVMF"
            )
    # Report the paths exactly as the config spells them: these strings are what
    # QEMU and containerd will use, and install.sh greps for them in /proc.
    bundle = Path(values["initrd"]).parent

    try:
        pod = json.loads(pod_file.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{pod_file}: not valid JSON ({exc})") from exc
    pod_name = pod.get("metadata", {}).get("name", "")
    if not pod_name:
        raise SystemExit(f"{pod_file}: metadata.name is missing")
    node_name = pod.get("spec", {}).get("nodeName", "")

    containers = pod.get("spec", {}).get("containers") or []
    if not containers or not containers[0].get("image"):
        raise SystemExit(f"{pod_file}: spec.containers[0].image is missing")
    image = containers[0]["image"]
    # image_archive names the packaged copy of the Pod image, if there is one.
    # A CoCo guest pulls the image itself through CDH, so loading it into the
    # host's docker is not enough -- it has to reach the registry the Pod names.
    # An empty value means "the image is expected to be there already".
    image_archive = ""
    for suffix in IMAGE_ARCHIVE_SUFFIXES:
        archive_path = pkg / "image" / image_tar_name(image, suffix)
        if archive_path.is_file():
            image_archive = str(archive_path.relative_to(pkg))
            break

    info = {
        "RUNTIME_HANDLER": handler,
        "RUNTIME_TYPE": fields["runtime_type"],
        "RUNTIME_PATH": fields.get("runtime_path", ""),
        "SNAPSHOTTER": fields.get("snapshotter", ""),
        "REMOTE_KATA_CONFIG": options["ConfigPath"],
        "REMOTE_BUNDLE_DIR": str(bundle),
        "PACKAGE_KATA_CONFIG": str(kata_config.relative_to(pkg)),
        "PACKAGE_RUNTIMECLASS": str(runtimeclass_file.relative_to(pkg)),
        "PACKAGE_TEST_POD": str(pod_file.relative_to(pkg)),
        "KATA_HYPERVISOR_SECTION": section,
        "TEST_POD_NAME": pod_name,
        "TEST_NODE_NAME": node_name,
        "TEST_IMAGE": image,
        "TEST_IMAGE_ARCHIVE": image_archive,
        # The deployment identity a consumer Pod has to copy. install.sh prints
        # it; an empty value means this render carried no identity.
        "TEST_POD_KERNEL_PARAMS": (pod.get("metadata", {}).get("annotations") or {}).get(
            KERNEL_PARAMS_ANNOTATION, ""
        ),
    }
    return info


def is_runtime_table(parts):
    return parts is not None and len(parts) > len(RUNTIMES_PREFIX) and tuple(
        parts[: len(RUNTIMES_PREFIX)]
    ) == RUNTIMES_PREFIX


def strip_handler_lines(lines, handler):
    """Drop one handler's table and its child tables from `lines`."""
    target = containerd_target(handler)
    kept = []
    skip = False
    for line in lines:
        parts = table_path(line)
        if parts is not None:
            skip = is_target_or_child(parts, target)
            if skip:
                continue
        if not skip:
            kept.append(line)
    return kept


def handler_blocks(path):
    """Return [(handler, lines)] for every runtime handler table in `path`."""
    blocks = []
    current = None
    for line in Path(path).read_text().splitlines():
        parts = table_path(line)
        if parts is not None:
            if is_runtime_table(parts):
                name = parts[len(RUNTIMES_PREFIX)]
                if current is None or current[0] != name:
                    current = (name, [])
                    blocks.append(current)
                current[1].append(line)
                continue
            current = None
            continue
        if current is not None:
            current[1].append(line)
    for _, lines in blocks:
        while lines and not lines[-1].strip():
            lines.pop()
    return blocks


def containerd_remove(path, handler, out):
    """Write `path` without `handler`'s tables, keeping everything else."""
    lines = strip_handler_lines(Path(path).read_text().splitlines(), handler)
    while lines and not lines[-1].strip():
        lines.pop()
    while lines and not lines[0].strip():
        lines.pop(0)
    Path(out).write_text("\n".join(lines) + "\n" if lines else "")


def containerd_handlers(path):
    """Return the runtime handler names defined in `path`, sorted."""
    return sorted({name for name, _ in handler_blocks(path)})


def flags(argv):
    """Parse `--flag value` pairs; repeated flags collect in order."""
    parsed, pending = {}, None
    for arg in argv:
        if arg.startswith("--"):
            pending = arg[2:]
            parsed.setdefault(pending, [])
        elif pending is None:
            raise SystemExit(f"unexpected argument: {arg}")
        else:
            parsed[pending].append(arg)
            pending = None
    return parsed


def one(parsed, name, default=""):
    """Return the single value of `--name`, or `default` when absent.

    A flag that takes no value (there is none today) would land here with an
    empty list; treating that as absent keeps the call sites readable.
    """
    return parsed[name][0] if parsed.get(name) else default



def main(argv):
    if not argv:
        raise SystemExit("missing command")
    command, rest = argv[0], argv[1:]
    if command == "info":
        if len(rest) != 1:
            raise SystemExit("info takes one package directory")
        for key, value in package_info(rest[0]).items():
            print(f"{key}={shlex.quote(value)}")
    elif command == "remove":
        parsed = flags(rest)
        containerd_remove(one(parsed, "file"), one(parsed, "handler"), one(parsed, "out"))
    elif command == "handlers":
        if len(rest) != 1:
            raise SystemExit("handlers takes one file")
        for name in containerd_handlers(rest[0]):
            print(name)
    else:
        raise SystemExit(f"unknown command: {command}")



main(sys.argv[1:])
TAA_PY
echo "== 卸载 containerd runtime handler =="

for cmd in sudo python3 containerd grep cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: $cmd is not installed or not in PATH" >&2
    exit 1
  fi
done

if ! pkg_settings="$(python3 "$taa_py" info "$pkg_dir")"; then
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
  python3 "$taa_py" remove \
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
if ! python3 "$taa_py" remove \
  --file "$dropin_dest" --handler "$RUNTIME_HANDLER" --out "$tmp_remove"; then
  echo "error: 从 $dropin_dest 删除 $RUNTIME_HANDLER 失败，未改动宿主" >&2
  exit 1
fi

remaining_taa="$(python3 "$taa_py" handlers "$tmp_remove" |
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
