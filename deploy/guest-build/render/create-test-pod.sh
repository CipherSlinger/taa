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
# created before a test-pod.yaml edit still carries the old kernel command line.
#
# Usage: sudo bash test/create-test-pod.sh
#
# Environment overrides:
#   MEASURE_SMP        vCPU count for the expected kernel command line
#                      (default: the Kata config's default_vcpus)
#   POD_READY_TIMEOUT  how long to wait for Ready (default 600s; the guest pulls
#                      and unpacks the container image itself, and a cold cache
#                      on the ~7 GiB DCU image takes minutes, not seconds)
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for cmd in kubectl python3 ps find; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: $cmd is not installed or not in PATH" >&2
    exit 1
  fi
done

# Wait until no process holds the DCU's /dev/vfio/<group> open.
#
# `kubectl delete --wait` returns when the Pod object is gone, but the shim can
# still be tearing the VM down after that. Applying the next Pod in that window
# starts a second VM on a card the first one has not released yet -- the one
# ordering mistake this script can make, and the reason it waits. The IOMMU
# groups come from sysfs (this image has no lspci); only open file descriptors
# are inspected, so the card's binding is never touched.
#
# A holder that does not go away is fatal here rather than a warning: creating
# the Pod anyway is the risky action, and a failure leaves the previous Pod
# deleted, which is easy to recover from.
#
# The two roots are overridable only so the helper can be tested locally, like
# taa-init's fixtures; production always uses the defaults.
SYSFS_PCI_DIR="${SYSFS_PCI_DIR:-/sys/bus/pci/devices}"
PROC_ROOT="${PROC_ROOT:-/proc}"
wait_dcu_vfio_release() {
  local timeout="${DCU_VFIO_RELEASE_TIMEOUT:-120}" waited=0 group holder groups dev
  groups=""
  for dev in "$SYSFS_PCI_DIR"/*; do
    [ -r "$dev/vendor" ] || continue
    [ "$(cat "$dev/vendor" 2>/dev/null)" = "0x1d94" ] || continue
    # Same filter as the guest hook: only the display/co-processor functions
    # are the card. Hygon root complexes and bridges share the vendor id, and
    # their IOMMU groups belong to the host, not to a Kata VM.
    case "$(cat "$dev/class" 2>/dev/null)" in
      0x03* | 0x0b40*) ;;
      *) continue ;;
    esac
    if ! group="$(readlink -f "$dev/iommu_group" 2>/dev/null)"; then
      continue
    fi
    group="${group##*/}"
    [ -n "$group" ] && groups="$groups $group"
  done
  groups="$(printf '%s\n' $groups | sort -u)"
  if [[ -z "$groups" ]]; then
    echo "no Hygon DCU on this host; nothing to wait for"
    return 0
  fi
  for group in $groups; do
    while :; do
      holder="$(find "$PROC_ROOT"/[0-9]*/fd -lname "/dev/vfio/$group" -print -quit 2>/dev/null || true)"
      [[ -z "$holder" ]] && break
      if (( waited >= timeout )); then
        echo "error: /dev/vfio/$group is still open after ${timeout}s (held by $holder)" >&2
        echo "hint: the previous VM has not exited; applying now can wedge the card" >&2
        return 1
      fi
      if (( waited == 0 )); then
        echo "waiting for /dev/vfio/$group to be released (held by $holder)"
      fi
      sleep 1
      waited=$((waited + 1))
    done
  done
  if (( waited > 0 )); then
    echo "DCU vfio group(s) released after ${waited}s"
  fi
  return 0
}

# The package's own reading of itself. Kept inline rather than shipped as a
# separate file: it is the only Python this script needs, and a package with
# one fewer moving part is one fewer thing that can go missing in transit.
taa_py="$(mktemp /tmp/taa-pkg.XXXXXX.py)"
cat > "$taa_py" <<'TAA_PY'
# Read the package's own settings. The delivery package ships no renderer, so
# the reading this script does is carried here: the handler block names the
# handler and its ConfigPath, the Kata config names the boot assets, and the
# test Pod names itself and carries the deployment identity.

import argparse, base64, json, re, shlex, sys
from pathlib import Path
from uuid import UUID


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


def pod_kernel_params(path):
    """Return a Pod manifest's kernel_params annotation, or "" when absent."""
    try:
        pod = json.loads(Path(path).read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: not valid JSON ({exc})") from exc
    annotations = pod.get("metadata", {}).get("annotations") or {}
    return annotations.get(KERNEL_PARAMS_ANNOTATION, "") if isinstance(annotations, dict) else ""


# The CSV2 measurement the boot check recomputes. The package ships no
# measure.py either: this is the same stdlib-only SM3 and hashes-table code
# the build host uses to quote the expected value, so the check on the target
# host needs no file that could travel separately.
import argparse
import base64
import hashlib
import sys
from uuid import UUID

# Fixed prefix observed on this host's Kata 3.17.0 CSV2 QEMU command line.
# It comes from arch/kernel defaults, not from the Kata config, so it is a
# constant here; KATA_APPEND lets a caller replace the whole string.
KATA_APPEND_FIXED = (
    "tsc=reliable no_timer_check rcupdate.rcu_expedited=1 "
    "i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 "
    "noreplace-smp reboot=k cryptomgr.notests net.ifnames=0 pci=lastbus=0 "
    "console=hvc0 console=hvc1"
)

CSV_HASH_TABLE_HEADER_GUID = "9438d606-4f22-4cc9-b479-a793d411fd21"
CSV_CMDLINE_ENTRY_GUID = "97d02dd8-bd20-4c94-aa78-e7714d36ab2a"
CSV_INITRD_ENTRY_GUID = "44baf731-3a2f-4bd7-9af1-41e29169781d"
CSV_KERNEL_ENTRY_GUID = "4de79437-abd2-427f-b835-d5b172d2045b"

ENTRY_SIZE = 16 + 2 + 32
MASK32 = 0xFFFFFFFF
SM3_IV = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
)


def _rotl(value, shift):
    shift %= 32
    return ((value << shift) | (value >> (32 - shift))) & MASK32


def _p0(value):
    return value ^ _rotl(value, 9) ^ _rotl(value, 17)


def _p1(value):
    return value ^ _rotl(value, 15) ^ _rotl(value, 23)


class SM3:
    """Pure-Python SM3 (GB/T 32905-2016), streaming like hashlib."""

    def __init__(self):
        self._state = list(SM3_IV)
        self._buffer = b""
        self._length = 0

    def update(self, data):
        self._length += len(data)
        buf = self._buffer + data
        full = len(buf) - (len(buf) % 64)
        for offset in range(0, full, 64):
            self._compress(buf[offset:offset + 64])
        self._buffer = buf[full:]

    def _compress(self, block):
        w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
        for j in range(16, 68):
            w.append(
                _p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15))
                ^ _rotl(w[j - 13], 7)
                ^ w[j - 6]
            )
        w1 = [w[j] ^ w[j + 4] for j in range(64)]

        a, b, c, d, e, f, g, h = self._state
        for j in range(64):
            t = 0x79CC4519 if j < 16 else 0x7A879D8A
            ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & MASK32, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            if j < 16:
                ff = a ^ b ^ c
                gg = e ^ f ^ g
            else:
                ff = (a & b) | (a & c) | (b & c)
                gg = (e & f) | ((~e & MASK32) & g)
            tt1 = (ff + d + ss2 + w1[j]) & MASK32
            tt2 = (gg + h + ss1 + w[j]) & MASK32
            d = c
            c = _rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = _rotl(f, 19)
            f = e
            e = _p0(tt2)
        self._state = [
            x ^ y for x, y in zip(self._state, (a, b, c, d, e, f, g, h))
        ]

    def digest(self):
        bit_length = self._length * 8
        pad = b"\x80" + b"\x00" * ((56 - (self._length + 1) % 64) % 64)
        final = self._buffer + pad + bit_length.to_bytes(8, "big")
        for offset in range(0, len(final), 64):
            self._compress(final[offset:offset + 64])
        return b"".join(x.to_bytes(4, "big") for x in self._state)


def guid_le(guid):
    return UUID("{" + guid + "}").bytes_le


def hashes_table(kernel_hash, initrd_hash, cmdline_hash):
    length = 16 + 2 + 3 * ENTRY_SIZE
    aligned = (length + 15) & ~15
    table = bytearray(aligned)
    table[0:16] = guid_le(CSV_HASH_TABLE_HEADER_GUID)
    table[16:18] = length.to_bytes(2, "little")

    entries = (
        (CSV_CMDLINE_ENTRY_GUID, cmdline_hash),
        (CSV_INITRD_ENTRY_GUID, initrd_hash),
        (CSV_KERNEL_ENTRY_GUID, kernel_hash),
    )
    offset = 18
    for guid, digest in entries:
        table[offset:offset + 16] = guid_le(guid)
        table[offset + 16:offset + 18] = ENTRY_SIZE.to_bytes(2, "little")
        table[offset + 18:offset + 18 + 32] = digest
        offset += ENTRY_SIZE
    return bytes(table)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.digest()


def cmdline_hash(path):
    with open(path, "rb") as handle:
        data = handle.read()
    if not data.endswith(b"\n"):
        raise SystemExit(
            "error: %s must end with a newline (the vendor tool replaces that "
            "last byte with NUL)" % path
        )
    return hashlib.sha256(data[:-1] + b"\x00").digest()


def measure(ovmf, kernel, initrd, cmdline_path):
    kernel_digest = sha256_file(kernel)
    initrd_digest = sha256_file(initrd)
    cmd_digest = cmdline_hash(cmdline_path)

    sm3 = SM3()
    with open(ovmf, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sm3.update(chunk)
    sm3.update(hashes_table(kernel_digest, initrd_digest, cmd_digest))
    return sm3.digest()


def parse_toml(path):
    """Parse the flat TOML subset the Kata config uses (section/key/value)."""
    sections = {}
    current = None
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1].strip()
                sections.setdefault(current, {})
                continue
            if current is None or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            sections[current][key] = value
    return sections


def as_bool(value, default):
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def kata_cmdline(config_path, section, smp, fixed):
    sections = parse_toml(config_path)
    hypervisor = sections.get(section)
    if hypervisor is None:
        raise SystemExit("error: section [%s] not found in %s" % (section, config_path))

    debug = as_bool(hypervisor.get("enable_debug"), False)
    disable_selinux = as_bool(hypervisor.get("disable_guest_selinux"), False)
    # debug_console_enabled lives in [agent.kata], not in the hypervisor or
    # runtime sections.
    debug_console = as_bool(
        sections.get("agent.kata", {}).get("debug_console_enabled"), False
    )

    if smp is None:
        try:
            smp = int(hypervisor.get("default_vcpus", "1"))
        except ValueError:
            smp = 1
        if smp <= 0:
            smp = 1

    parts = [
        fixed,
        "debug" if debug else "quiet",
        "panic=1",
        "nr_cpus=%d" % smp,
        "selinux=%d" % (0 if disable_selinux else 1),
        "scsi_mod.scan=none",
    ]
    if debug:
        parts.append("agent.log=debug")
    if debug_console:
        parts.append("agent.debug_console")
        parts.append("agent.debug_console_vport=1026")
    kernel_params = hypervisor.get("kernel_params", "").strip()
    if kernel_params:
        parts.append(kernel_params)
    return " ".join(part for part in parts if part)


def measure_main(argv=None):
    parser = argparse.ArgumentParser(description="CSV2 launch-digest helper")
    sub = parser.add_subparsers(dest="command", required=True)

    cmd = sub.add_parser("cmdline", help="print the expected QEMU -append string")
    cmd.add_argument("--config", required=True)
    cmd.add_argument("--section", default="hypervisor.qemu")
    cmd.add_argument("--smp", type=int)
    cmd.add_argument("--fixed", default=KATA_APPEND_FIXED)

    dig = sub.add_parser("digest", help="print the CSV2 MEASUREMENT")
    dig.add_argument("--ovmf", required=True)
    dig.add_argument("--kernel", required=True)
    dig.add_argument("--initrd", required=True)
    dig.add_argument("--cmdline", required=True)

    args = parser.parse_args(argv)
    if args.command == "cmdline":
        print(kata_cmdline(args.config, args.section, args.smp, args.fixed))
        return 0

    digest = measure(args.ovmf, args.kernel, args.initrd, args.cmdline)
    print("hex=%s" % digest.hex())
    print("base64=%s" % base64.b64encode(digest).decode("ascii"))
    return 0


def main(argv):
    if not argv:
        raise SystemExit("missing command")
    command, rest = argv[0], argv[1:]
    if command == "info":
        if len(rest) != 1:
            raise SystemExit("info takes one package directory")
        for key, value in package_info(rest[0]).items():
            print(f"{key}={shlex.quote(value)}")
    elif command == "kernel-params":
        if len(rest) != 1:
            raise SystemExit("kernel-params takes one Pod manifest")
        print(pod_kernel_params(rest[0]))
    elif command in ("cmdline", "digest"):
        measure_main([command] + rest)
    else:
        raise SystemExit(f"unknown command: {command}")


main(sys.argv[1:])
TAA_PY
# The package describes itself; the reader above also refuses a moved or
# incomplete directory, so a Pod is never created against a half-assembled
# package.
if ! pkg_settings="$(python3 "$taa_py" info "$pkg_dir")"; then
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
# something other than this package. The kernel_params this Pod does carry is
# its own deployment identity, rendered into the packaged manifest, so it is
# left exactly as shipped.
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
wait_dcu_vfio_release
kubectl apply -f "$pod_manifest"

echo
echo "== 2. 等待测试 Pod Ready =="
ready_timeout="${POD_READY_TIMEOUT:-600}"
if ! kubectl wait --for=condition=Ready "pod/$TEST_POD_NAME" --timeout="${ready_timeout}s"; then
  echo "error: test Pod did not become Ready within ${ready_timeout}s; status and events follow" >&2
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
# host plus this Pod's kernel_params annotation, which Kata appends to it. A
# difference from the running VM then means the manifest's identity annotation
# changed or the host's Kata drifted, not that the package is stale.
package_kata_config="$pkg_dir/$PACKAGE_KATA_CONFIG"
kata_section="$KATA_HYPERVISOR_SECTION"
expected_hex=""
expected_cmdline=""
smp_args=()
[[ -n "${MEASURE_SMP:-}" ]] && smp_args=(--smp "$MEASURE_SMP")
if expected_cmdline="$(python3 "$taa_py" cmdline \
    --config "$package_kata_config" --section "$kata_section" \
    ${smp_args[@]+"${smp_args[@]}"} 2>/dev/null)"; then
  # Kata appends the Pod's kernel_params annotation to the config's parameters,
  # so the identity is part of the measured -append. Read it from the manifest
  # actually being applied, not re-derived, so an operator edit is exactly what
  # is hashed.
  pod_kernel_params="$(python3 "$taa_py" kernel-params "$pod_manifest" 2>/dev/null || true)"
  if [[ -n "$pod_kernel_params" ]]; then
    expected_cmdline="$expected_cmdline $pod_kernel_params"
  fi
  tmp_expected="$(mktemp /tmp/taa-expected.XXXXXX.txt)"
  printf '%s\n' "$expected_cmdline" > "$tmp_expected"
  if expected_out="$(python3 "$taa_py" digest \
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
    # write exactly one back: the digest helper replaces only the final byte with NUL,
    # so a second trailing newline would be hashed and yield a digest that never
    # matches the running VM.
    append_value="$(tr '\0' '\n' < "/proc/$qpid/cmdline" |
      grep -A1 -- '^-append$' | tail -n1 || true)"
    if [[ -z "$append_value" ]]; then
      echo "warning: 未能从 /proc/$qpid/cmdline 取到 -append" >&2
    else
      printf '%s\n' "$append_value" > "$tmp_append"
      if ! actual_measure="$(python3 "$taa_py" digest \
        --ovmf "$REMOTE_BUNDLE_DIR/OVMF.fd" \
        --kernel "$REMOTE_BUNDLE_DIR/vmlinuz" \
        --initrd "$REMOTE_BUNDLE_DIR/initramfs.img" \
        --cmdline "$tmp_append")"; then
        echo "warning: 内嵌度量计算失败，跳过度量核对" >&2
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
