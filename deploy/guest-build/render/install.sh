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
# from kata-config.toml. The reader embedded below refuses a package whose
# absolute paths do not name its own files, so a moved or half-assembled
# directory fails before anything is touched.
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
taa_py=""
cleanup() {
  if [[ -n "$taa_py" ]]; then rm -f "$taa_py"; fi
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

# The package's own reading of itself. Kept inline rather than shipped as a
# separate file: it is the only Python this script needs, and a package with
# one fewer moving part is one fewer thing that can go missing in transit.
taa_py="$(mktemp /tmp/taa-pkg.XXXXXX.py)"
cat > "$taa_py" <<'TAA_PY'
# Read the package and rewrite the containerd configuration. The delivery
# package ships no renderer, so this script carries the host side of what the
# build host's renderer did -- the same TOML handling and the same checks -- so
# what runs here can be reviewed as what it is.

import glob, json, re, shlex, sys
from pathlib import Path


CRI = "io.containerd.grpc.v1.cri"
RUNTIMES = ("plugins", CRI, "containerd", "runtimes")
KERNEL_PARAMS_ANNOTATION = "io.katacontainers.config.hypervisor.kernel_params"
IMAGE_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar")
DROPIN_HEADER = """\
# Generated by TAA install.sh and uninstall.sh. containerd loads this file last
# and the last file defining a runtime handler replaces the whole
# plugins."io.containerd.grpc.v1.cri" tree, so this drop-in carries the host's
# current runtimes map and the handlers TAA packages installed. Seeded once from
# the host, then kept in the package and rewritten on every install/uninstall;
# do not edit by hand."""


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
        "KATA_HYPERVISOR_SECTION": section,
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


def containerd_block(handler, runtime_type, runtime_path, snapshotter, kata_config):
    handler_name = toml_string(handler)
    base = f'[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.{handler_name}]'
    options = f'[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.{handler_name}.options]'
    block = [base, f"runtime_type = {toml_string(runtime_type)}"]
    if runtime_path:
        block.append(f"runtime_path = {toml_string(runtime_path)}")
    block.extend(
        [
            "privileged_without_host_devices = true",
            'pod_annotations = ["io.katacontainers.*"]',
        ]
    )
    if snapshotter:
        block.append(f"snapshotter = {toml_string(snapshotter)}")
    block.extend(["", options, f"ConfigPath = {toml_string(kata_config)}"])
    return block


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


def read_imports(config):
    """Return the `imports` array of `config`, without expanding globs."""
    imports = []
    buf = ""
    collecting = False
    for line in Path(config).read_text().splitlines():
        if not collecting:
            if not active_key(line, "imports"):
                continue
            collecting = True
            buf = line.split("=", 1)[1]
        else:
            buf += " " + line.strip()
        if "]" in buf:
            break
    for raw in re.findall(r'"((?:[^"\\]|\\.)*)"', buf):
        imports.append(json.loads(f'"{raw}"'))
    return imports


def expand_imports(config):
    """Expand `imports` into the files containerd loads, in load order."""
    base_dir = Path(config).resolve().parent
    paths = []
    for entry in read_imports(config):
        path = entry if Path(entry).is_absolute() else str(base_dir / entry)
        if any(ch in path for ch in "*?["):
            matches = sorted(glob.glob(path))
        else:
            matches = [path]
        paths.extend(match for match in matches if Path(match).is_file())
    return paths


def defines_runtimes(path):
    return any(is_runtime_table(table_path(line))
               for line in Path(path).read_text().splitlines())


def effective_runtimes_source(config, exclude_prefix=""):
    """Return the file whose runtimes map is the last one containerd loads.

    TAA-owned drop-ins (matching `exclude_prefix`) are skipped: they are derived
    from the host's own files, so deriving a new one from them would freeze the
    host's configuration at the first install.
    """
    winner = Path(config)
    for path in [config, *expand_imports(config)]:
        if exclude_prefix and Path(path).name.startswith(exclude_prefix):
            continue
        if defines_runtimes(path):
            winner = Path(path)
    return winner


def cri_subtree_lines(path):
    """Return only the CRI plugin tables of `path`.

    Used when the host has no imported file defining runtimes: copying the main
    config wholesale into a drop-in would replay every other plugin section and
    the `imports` array itself.
    """
    out = []
    keep = False
    for line in Path(path).read_text().splitlines():
        parts = table_path(line)
        if parts is not None:
            keep = tuple(parts[:2]) == ("plugins", CRI_PLUGIN)
            if keep:
                out.append(line)
            continue
        if keep:
            out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return out


def containerd_dropin(config, carry, exclude_prefix, handler, runtime_type,
                      runtime_path, snapshotter, kata_config, out, base=None):
    """Write the TAA-owned drop-in: host runtimes map + this package's handler.

    `base` is the package's existing drop-in. Reusing it makes the package own
    the snapshot: a host change after the first install does not silently
    rewrite the file, and uninstall can take the handler back out again.
    Without it the snapshot comes from the file containerd loads last, ignoring
    TAA-owned files so a reinstall does not derive from its own output.
    """
    if base:
        base_path = Path(base)
        if not base_path.is_file():
            raise SystemExit(f"{base}: base drop-in does not exist")
        lines = base_path.read_text().splitlines()
    else:
        base_path = effective_runtimes_source(config, exclude_prefix)
        if base_path.resolve() == Path(config).resolve():
            lines = cri_subtree_lines(base_path)
        else:
            lines = base_path.read_text().splitlines()
    # A package copy already starts with the generated header; drop it before
    # prepending it again, so a reinstall stays byte-for-byte idempotent.
    header = DROPIN_HEADER.splitlines()
    if lines[: len(header)] == header:
        lines = lines[len(header):]
        while lines and not lines[0].strip():
            lines.pop(0)
    base_blocks = dict(handler_blocks(base_path))
    carried = {}
    for path in carry:
        if not Path(path).is_file():
            continue
        for name, block in handler_blocks(path):
            if name == handler:
                continue
            # The installed drop-in is fresher than the package copy: another
            # TAA package may have updated its own handler since this package
            # last ran. Carry the block over the base's version, but leave an
            # identical block where it is so a reinstall stays byte-identical.
            if base_blocks.get(name) == block:
                continue
            carried[name] = block

    managed = set(carried) | {handler}
    for name in managed:
        lines = strip_handler_lines(lines, name)
    while lines and not lines[-1].strip():
        lines.pop()
    while lines and not lines[0].strip():
        lines.pop(0)

    out_lines = DROPIN_HEADER.splitlines() + [""] + lines
    for name, block in carried.items():
        out_lines.extend(["", *block])
    out_lines.extend(
        ["", *containerd_block(handler, runtime_type, runtime_path, snapshotter, kata_config)]
    )
    Path(out).write_text("\n".join(out_lines) + "\n")


def containerd_stage(config, extra, out):
    """Copy `config`, replacing its imports with the expanded list plus `extra`.

    Lets the installer ask containerd to resolve the prospective configuration
    before anything under /etc changes.
    """
    lines = Path(config).read_text().splitlines()
    start = None
    for index, line in enumerate(lines):
        if active_key(line, "imports"):
            start = index
            break
    if start is None:
        raise SystemExit(f"{config}: no imports array to extend")
    end = start
    depth = lines[start].count("[") - lines[start].count("]")
    while depth > 0 and end + 1 < len(lines):
        end += 1
        depth += lines[end].count("[") - lines[end].count("]")
    entries = [*expand_imports(config), extra]
    replacement = "imports = [" + ", ".join(toml_string(entry) for entry in entries) + "]"
    Path(out).write_text("\n".join(lines[:start] + [replacement] + lines[end + 1:]) + "\n")


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
    elif command == "dropin":
        parsed = flags(rest)
        containerd_dropin(
            one(parsed, "config"), parsed.get("carry", []),
            one(parsed, "exclude-prefix", "zz-taa"),
            one(parsed, "handler"), one(parsed, "runtime-type"),
            one(parsed, "runtime-path"), one(parsed, "snapshotter"),
            one(parsed, "kata-config"), one(parsed, "out"),
            base=one(parsed, "base"),
        )
    elif command == "stage":
        parsed = flags(rest)
        containerd_stage(one(parsed, "config"), one(parsed, "extra"), one(parsed, "out"))
    else:
        raise SystemExit(f"unknown command: {command}")



main(sys.argv[1:])
TAA_PY
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
if ! pkg_settings="$(python3 "$taa_py" info "$pkg_dir")"; then
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
if ! python3 "$taa_py" dropin \
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
if ! python3 "$taa_py" stage \
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
