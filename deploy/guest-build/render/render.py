#!/usr/bin/env python3
"""Render the on-host artifacts of the TAA-in-initrd flow.

Generation runs on the build host so the same files can be installed by
`launch` and shipped as a delivery package. Stdlib only; nothing here touches
the network or the target host.
"""

import argparse
import glob
import json
import re
import shlex
import sys
from pathlib import Path

RDINIT = "rdinit=/usr/local/bin/taa-init"

# The identity keys taa-init reads back from /proc/cmdline. Kept here so the
# package's editable identity file cannot grow a key the guest would silently
# ignore, and so a re-render can drop the whole set before applying the file
# (deleting a line has to delete the parameter, not leave a stale one behind).
# Each key is the environment variable taa-init exports from it, in lower case:
# `taa.taa_llm_endpoint` becomes TAA_LLM_ENDPOINT. The list stays here so a typo
# in the editable identity file fails the install; taa-init itself accepts any
# well-formed `taa.<key>` and applies the same case mapping, so a new setting
# only has to be added here.
IDENTITY_KEYS = (
    "platform_ip",
    "docker_id",
    "platform_public_key",
    "platform_sm2_id",
    "contract_id",
    "contract_type",
    "taa_llm_endpoint",
    "taa_addr",
    # Kernel modules the guest loads before starting TAA (comma-separated). Only
    # the DCU roles set it (hycu); everywhere else it is absent, which is what
    # taa-init treats as "load nothing".
    "taa_modules",
    # Wrapped copy of the SM2 private scalar. SM4-GCM under SM3(hardware sealing
    # key || CONTRACT_ID)[:16], so it is ciphertext, not the key itself: a host
    # that can read the command line still cannot decrypt it, and re-injecting
    # it is exactly the recovery path TAA implements.
    "taasecretkey",
)


def toml_string(value):
    return json.dumps(value)


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


def active_key(line, key):
    stripped = line.lstrip()
    return not stripped.startswith("#") and re.match(rf"^\s*{re.escape(key)}\s*=", line)


def read_identity_file(path):
    """Parse a `taa.<key>=<value>` file into kernel parameters.

    One token per line; blank lines and `#` comments are ignored. The format is
    the command line itself rather than `NAME=value` env syntax on purpose: the
    file is not sourceable, so a stray edit cannot end up exported in a shell,
    and what it holds is exactly what the kernel will be given.

    Validation is strict -- unknown key, duplicate key, empty or whitespace-
    bearing value are all fatal. A typo must fail the install, not become a
    parameter the guest drops on the floor while everything else looks fine.
    """
    tokens = []
    seen = set()
    for lineno, raw in enumerate(Path(path).read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise SystemExit(f"{path}:{lineno}: missing '=': {raw!r}")
        if not key.startswith("taa.") or key[len("taa."):] not in IDENTITY_KEYS:
            raise SystemExit(
                f"{path}:{lineno}: unknown identity key: {key} "
                f"(allowed: {', '.join('taa.' + k for k in IDENTITY_KEYS)})"
            )
        if not value:
            raise SystemExit(f"{path}:{lineno}: empty value for {key}")
        if any(ch.isspace() for ch in value):
            raise SystemExit(f"{path}:{lineno}: whitespace in the value for {key}")
        if key in seen:
            raise SystemExit(f"{path}:{lineno}: duplicate key: {key}")
        seen.add(key)
        tokens.append(line)
    return tokens


def render_kata_config(template, section, bundle_dir, out, extra_params=(),
                       replace_identity=False, memory_mib=None):
    """Point one hypervisor section at the TAA bundle; leave everything else.

    memory_mib overrides the section's default_memory. It is not cosmetic: a
    CSV2 guest's writable root is a tmpfs capped at roughly half the guest RAM,
    and the CDH unpacks the container image into it. At the stock 2048 the
    slim-v2 image (1.92 GB unpacked) fails with "Failed to unpack layer" and
    the Pod lands in StartError -- which reads like an initrd problem but is not
    one. The template's value is sized for a minimal guest image, not this one.
    """
    path = Path(template)
    lines = path.read_text().splitlines()
    out_lines = []
    seen = {"kernel": False, "initrd": False, "firmware": False, "kernel_params": False,
            "default_memory": False}
    in_target = False
    target_seen = False

    def with_extra(params):
        """Drop parameters an extra one replaces, then append the extras.

        A re-render must be idempotent: appending blindly would stack one
        `taa.platform_ip=` per render, and the last one happens to win only by
        luck (the guest parser would take whichever came last).

        With replace_identity the whole identity set is dropped first, so a key
        deleted from the editable identity file disappears from the command line
        instead of surviving with its previous value.
        """
        drop = {p.split("=", 1)[0] for p in extra_params}
        if replace_identity:
            # Drop every identity token, not only the keys known here: taa-init
            # exports any well-formed `taa.<key>`, so a token left behind by an
            # older render would still take effect and could silently shadow the
            # edited file.
            drop |= {p.split("=", 1)[0] for p in params
                     if p.split("=", 1)[0].startswith("taa.")}
        kept = [p for p in params if p.split("=", 1)[0] not in drop]
        return kept + list(extra_params)

    def emit_missing():
        if not seen["kernel"]:
            out_lines.append(f'kernel = {toml_string(bundle_dir + "/vmlinuz")}')
            seen["kernel"] = True
        if not seen["initrd"]:
            out_lines.append(f'initrd = {toml_string(bundle_dir + "/initramfs.img")}')
            seen["initrd"] = True
        if not seen["firmware"]:
            out_lines.append(f'firmware = {toml_string(bundle_dir + "/OVMF.fd")}')
            seen["firmware"] = True
        if not seen["kernel_params"]:
            params = with_extra([RDINIT])
            out_lines.append(f'kernel_params = {toml_string(" ".join(params))}')
            seen["kernel_params"] = True
        # A template without default_memory still gets the requested value:
        # silently keeping the default would boot a guest too small for the
        # image, and that failure reads as an unrelated unpack error.
        if memory_mib is not None and not seen["default_memory"]:
            out_lines.append(f"default_memory = {memory_mib}")
            seen["default_memory"] = True

    for line in lines:
        table = table_path(line)
        if table is not None:
            if in_target:
                emit_missing()
            in_target = ".".join(table) == section
            if in_target:
                target_seen = True
            out_lines.append(line)
            continue

        if not in_target:
            out_lines.append(line)
            continue

        if active_key(line, "image"):
            out_lines.append("# " + line)
            continue
        if active_key(line, "kernel"):
            out_lines.append(f'kernel = {toml_string(bundle_dir + "/vmlinuz")}')
            seen["kernel"] = True
            continue
        if active_key(line, "initrd"):
            out_lines.append(f'initrd = {toml_string(bundle_dir + "/initramfs.img")}')
            seen["initrd"] = True
            continue
        if active_key(line, "firmware"):
            out_lines.append(f'firmware = {toml_string(bundle_dir + "/OVMF.fd")}')
            seen["firmware"] = True
            continue
        if active_key(line, "kernel_params"):
            match = re.match(r'^\s*kernel_params\s*=\s*"([^"]*)"', line)
            if not match:
                raise SystemExit(f"unrecognized kernel_params line: {line}")
            existing = match.group(1).strip()
            params = shlex.split(existing) if existing else []
            # Strip both keys: init= is dead config once /init exists in the
            # initrd (the kernel tries rdinit= first), and a stale value would
            # suggest it still has an effect.
            params = [p for p in params if not p.startswith("init=") and not p.startswith("rdinit=")]
            params.insert(0, RDINIT)
            params = with_extra(params)
            out_lines.append(f'kernel_params = {toml_string(" ".join(params))}')
            seen["kernel_params"] = True
            continue
        if memory_mib is not None and active_key(line, "default_memory"):
            # Replace rather than append: the section must keep exactly one
            # default_memory, and a duplicate key is invalid TOML.
            out_lines.append(f"default_memory = {memory_mib}")
            seen["default_memory"] = True
            continue
        out_lines.append(line)

    if in_target:
        emit_missing()
    if not target_seen:
        if out_lines and out_lines[-1].strip():
            out_lines.append("")
        out_lines.append(f"[{section}]")
        emit_missing()

    Path(out).write_text("\n".join(out_lines) + "\n")
    validate_kata_config(out, section)


def validate_kata_config(path, section):
    """Refuse to publish a config that would boot the wrong initrd."""
    current = None
    values = {}
    for line in Path(path).read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]") and not stripped.startswith("[["):
            current = stripped[1:-1].strip()
            continue
        if current != section or stripped.startswith("#"):
            continue
        match = re.match(r"^(image|kernel|initrd|firmware|kernel_params)\s*=\s*(.*)$", stripped)
        if match:
            values[match.group(1)] = match.group(2)
    if "image" in values:
        raise SystemExit("active image setting remains in target Kata hypervisor section")
    for key in ("kernel", "initrd", "firmware", "kernel_params"):
        if key not in values:
            raise SystemExit(f"missing active {key} in target Kata hypervisor section")
    if RDINIT not in values["kernel_params"]:
        raise SystemExit(f"kernel_params does not contain {RDINIT}")


def containerd_target(handler):
    return ["plugins", "io.containerd.grpc.v1.cri", "containerd", "runtimes", handler]


def is_target_or_child(parts, target):
    return parts is not None and len(parts) >= len(target) and parts[: len(target)] == target


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


def containerd_merge(config, handler, runtime_type, runtime_path, snapshotter, kata_config, out):
    target = containerd_target(handler)
    lines = Path(config).read_text().splitlines()
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

    # Collapse the blank lines the removal leaves at the end of the file.
    while kept and not kept[-1].strip():
        kept.pop()
    if kept and kept[-1].strip():
        kept.append("")
    kept.extend(containerd_block(handler, runtime_type, runtime_path, snapshotter, kata_config))
    Path(out).write_text("\n".join(kept) + "\n")


def containerd_strip(config, handler):
    """Inverse of containerd_merge: drop the handler and its child table."""
    lines = strip_handler_lines(Path(config).read_text().splitlines(), handler)
    while lines and not lines[-1].strip():
        lines.pop()
    Path(config).write_text("\n".join(lines) + "\n")


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


CRI_PLUGIN = "io.containerd.grpc.v1.cri"

# Tables under this prefix are the runtime handlers. containerd loads the main
# config and then its `imports` in order, and the last file that defines any of
# these tables replaces the whole CRI plugin tree -- the plugins map is merged
# key by key, and the CRI tree is one value. A drop-in holding only the handler
# it adds therefore erases every other handler, so one has to carry them all.
RUNTIMES_PREFIX = ("plugins", CRI_PLUGIN, "containerd", "runtimes")


def is_runtime_table(parts):
    return parts is not None and len(parts) > len(RUNTIMES_PREFIX) and tuple(
        parts[: len(RUNTIMES_PREFIX)]
    ) == RUNTIMES_PREFIX


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


DROPIN_HEADER = """\
# Generated by TAA install.sh and uninstall.sh. containerd loads this file last
# and the last file defining a runtime handler replaces the whole
# plugins."io.containerd.grpc.v1.cri" tree, so this drop-in carries the host's
# current runtimes map and the handlers TAA packages installed. Seeded once from
# the host, then kept in the package and rewritten on every install/uninstall;
# do not edit by hand."""


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


def containerd_handlers(path):
    """Return the runtime handler names defined in `path`, sorted."""
    return sorted({name for name, _ in handler_blocks(path)})


def containerd_remove(path, handler, out):
    """Write `path` without `handler`'s tables, keeping everything else."""
    lines = strip_handler_lines(Path(path).read_text().splitlines(), handler)
    while lines and not lines[-1].strip():
        lines.pop()
    while lines and not lines[0].strip():
        lines.pop(0)
    Path(out).write_text("\n".join(lines) + "\n" if lines else "")


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


# Archive suffixes docker load accepts, longest first so `.tar.gz` is not read
# as `.gz` of `.tar`.
IMAGE_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar")


def archive_suffix(path):
    """Return the recognized archive suffix of `path`, or `.tar` if none matches."""
    name = str(path)
    for suffix in IMAGE_ARCHIVE_SUFFIXES:
        if name.endswith(suffix):
            return suffix
    return ".tar"


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
    kata_config = pkg / "config" / "kata-config.toml"
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
        "PACKAGE_IDENTITY_FILE": "config/env.txt",
        "PACKAGE_RUNTIMECLASS": str(runtimeclass_file.relative_to(pkg)),
        "PACKAGE_TEST_POD": str(pod_file.relative_to(pkg)),
        "KATA_HYPERVISOR_SECTION": section,
        "TEST_POD_NAME": pod_name,
        "TEST_NODE_NAME": node_name,
        "TEST_IMAGE": image,
        "TEST_IMAGE_ARCHIVE": image_archive,
    }
    return info


def parse_device_resources(specs):
    """Turn repeated NAME=COUNT options into a {name: count} mapping."""
    resources = {}
    for spec in specs:
        name, sep, count = spec.partition("=")
        name, count = name.strip(), count.strip()
        if not sep or not name or not count:
            raise SystemExit(f"--device-resource expects NAME=COUNT, got {spec!r}")
        if not count.isdigit():
            raise SystemExit(f"--device-resource count must be a non-negative integer: {spec!r}")
        resources[name] = count
    return resources


def render_k8s(handler, pod_name, node_name, image, annotations_json, out_dir,
               run_as_user="", pod_dir="", device_resources=None):
    try:
        annotations = json.loads(annotations_json)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--annotations is not valid JSON: {exc}") from exc
    if not isinstance(annotations, dict):
        raise SystemExit("--annotations must be a JSON object")

    metadata = {"name": pod_name}
    if annotations:
        metadata["annotations"] = annotations

    runtimeclass = {
        "apiVersion": "node.k8s.io/v1",
        "kind": "RuntimeClass",
        "metadata": {"name": handler},
        "handler": handler,
    }
    container = {
        "name": "test",
        "image": image,
        "command": ["sh", "-c", "echo hello from kata csv2 taa guest; sleep 3600"],
    }
    # A numeric uid is not a preference here, it is what lets the Pod start at
    # all under the nydus guest-pull snapshotter: containerd resolves a *named*
    # user against /etc/passwd on the host-side snapshot, which in that mode
    # carries metadata only, so a name fails with "mount callback failed ...
    # /etc/passwd: no such file or directory" before the guest is reached.
    if str(run_as_user).strip():
        container["securityContext"] = {"runAsUser": int(run_as_user)}
    # A device-plugin resource has to be requested and limited; requesting it
    # without the limit leaves the extended resource unrestricted and the Pod is
    # rejected. The count is echoed in both, which is what the plugin expects.
    if device_resources:
        container["resources"] = {
            "requests": dict(device_resources),
            "limits": dict(device_resources),
        }
    pod_spec = {
        "runtimeClassName": handler,
        "restartPolicy": "Never",
        "containers": [container],
    }
    # nodeName pins the test Pod to the node being deployed. Leaving it out
    # keeps a delivered package schedulable on another node.
    if node_name:
        pod_spec["nodeName"] = node_name
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": metadata,
        "spec": pod_spec,
    }

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "runtimeclass.yaml").write_text(json.dumps(runtimeclass, indent=2) + "\n")
    # The test Pod is not part of the runtime the package installs -- it only
    # exercises it -- so it can be placed beside the test scripts instead of
    # with the RuntimeClass every consumer Pod depends on.
    pod_out = Path(pod_dir) if pod_dir else out
    pod_out.mkdir(parents=True, exist_ok=True)
    (pod_out / "test-pod.yaml").write_text(json.dumps(pod, indent=2) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    kata = sub.add_parser("kata-config", help="rewrite one Kata hypervisor section")
    kata.add_argument("--template", required=True)
    kata.add_argument("--section", required=True)
    kata.add_argument("--bundle-dir", required=True)
    kata.add_argument(
        "--param",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="extra kernel parameter, repeatable; replaces an existing one with "
        "the same key so a re-render cannot duplicate tokens",
    )
    kata.add_argument(
        "--param-file",
        metavar="PATH",
        help="file of `taa.<key>=<value>` lines; replaces the whole identity set, "
        "so a removed line also removes the parameter",
    )
    kata.add_argument(
        "--memory-mib",
        type=int,
        metavar="MIB",
        help="override the section's default_memory; a CSV2 guest sizes its "
        "writable root at about half of this, and the container image is "
        "unpacked into it",
    )
    kata.add_argument("--out", required=True)

    merge = sub.add_parser("containerd-merge", help="add or replace the runtime handler")
    merge.add_argument("--config", required=True)
    merge.add_argument("--handler", required=True)
    merge.add_argument("--runtime-type", required=True)
    merge.add_argument("--runtime-path", default="")
    merge.add_argument("--snapshotter", default="")
    merge.add_argument("--kata-config", required=True)
    merge.add_argument("--out")

    fragment = sub.add_parser("containerd-fragment", help="print the handler block only")
    fragment.add_argument("--handler", required=True)
    fragment.add_argument("--runtime-type", required=True)
    fragment.add_argument("--runtime-path", default="")
    fragment.add_argument("--snapshotter", default="")
    fragment.add_argument("--kata-config", required=True)
    fragment.add_argument("--out", required=True)

    strip = sub.add_parser("containerd-strip", help="remove the runtime handler")
    strip.add_argument("--config", required=True)
    strip.add_argument("--handler", required=True)

    source = sub.add_parser(
        "containerd-effective-source",
        help="print the file whose runtime map containerd loads last",
    )
    source.add_argument("--config", required=True)
    source.add_argument("--exclude-prefix", default="")

    dropin = sub.add_parser(
        "containerd-dropin",
        help="write a self-contained handler drop-in: host runtimes + one handler",
    )
    dropin.add_argument("--config", required=True)
    dropin.add_argument("--carry", action="append", default=[],
                        help="existing TAA drop-in whose other handlers must survive")
    dropin.add_argument(
        "--base",
        default="",
        help="package drop-in to reuse as the snapshot instead of the host's "
             "last effective file",
    )
    dropin.add_argument("--exclude-prefix", default="zz-taa")
    dropin.add_argument("--handler", required=True)
    dropin.add_argument("--runtime-type", required=True)
    dropin.add_argument("--runtime-path", default="")
    dropin.add_argument("--snapshotter", default="")
    dropin.add_argument("--kata-config", required=True)
    dropin.add_argument("--out", required=True)

    handlers = sub.add_parser(
        "containerd-handlers",
        help="print the runtime handler names defined in a drop-in",
    )
    handlers.add_argument("--file", required=True)

    remove = sub.add_parser(
        "containerd-remove",
        help="write a drop-in without one runtime handler",
    )
    remove.add_argument("--file", required=True)
    remove.add_argument("--handler", required=True)
    remove.add_argument("--out", required=True)

    stage = sub.add_parser(
        "containerd-stage",
        help="copy a containerd config with one extra import appended",
    )
    stage.add_argument("--config", required=True)
    stage.add_argument("--extra", required=True)
    stage.add_argument("--out", required=True)

    info = sub.add_parser(
        "package-info",
        help="derive the installer's settings from a rendered package (KEY=value lines)",
    )
    info.add_argument("--dir", required=True, help="package root")

    archive_name = sub.add_parser(
        "image-archive-name",
        help="print the filename a packaged image archive is stored under",
    )
    archive_name.add_argument("--image", required=True)
    archive_name.add_argument(
        "--like",
        default="",
        help="source archive whose suffix the packaged name should keep",
    )

    k8s = sub.add_parser("k8s", help="write RuntimeClass and test Pod manifests")
    k8s.add_argument("--handler", required=True)
    k8s.add_argument("--pod", required=True)
    k8s.add_argument("--node", default="")
    k8s.add_argument("--image", required=True)
    k8s.add_argument("--annotations", default="{}")
    k8s.add_argument(
        "--run-as-user",
        default="",
        help="numeric uid for the test container (a name cannot be resolved under guest-pull)",
    )
    k8s.add_argument("--out-dir", required=True)
    k8s.add_argument(
        "--pod-dir",
        default="",
        help="write test-pod.yaml here instead of into --out-dir",
    )
    k8s.add_argument(
        "--device-resource",
        action="append",
        default=[],
        metavar="NAME=COUNT",
        help="extended resource the test container requests and is limited to (repeatable)",
    )

    args = parser.parse_args(argv)

    if args.command == "kata-config":
        params = list(args.param)
        if args.param_file:
            params += read_identity_file(args.param_file)
        render_kata_config(
            args.template,
            args.section,
            args.bundle_dir,
            args.out,
            params,
            replace_identity=bool(args.param_file),
            memory_mib=args.memory_mib,
        )
    elif args.command == "containerd-merge":
        containerd_merge(
            args.config,
            args.handler,
            args.runtime_type,
            args.runtime_path,
            args.snapshotter,
            args.kata_config,
            args.out or args.config,
        )
    elif args.command == "containerd-fragment":
        block = containerd_block(
            args.handler, args.runtime_type, args.runtime_path, args.snapshotter, args.kata_config
        )
        Path(args.out).write_text("\n".join(block) + "\n")
    elif args.command == "containerd-strip":
        containerd_strip(args.config, args.handler)
    elif args.command == "containerd-effective-source":
        print(effective_runtimes_source(args.config, args.exclude_prefix))
    elif args.command == "containerd-dropin":
        containerd_dropin(
            args.config,
            args.carry,
            args.exclude_prefix,
            args.handler,
            args.runtime_type,
            args.runtime_path,
            args.snapshotter,
            args.kata_config,
            args.out,
            base=args.base,
        )
    elif args.command == "containerd-handlers":
        for name in containerd_handlers(args.file):
            print(name)
    elif args.command == "containerd-remove":
        containerd_remove(args.file, args.handler, args.out)
    elif args.command == "containerd-stage":
        containerd_stage(args.config, args.extra, args.out)
    elif args.command == "package-info":
        for key, value in package_info(args.dir).items():
            print(f"{key}={shlex.quote(value)}")
    elif args.command == "image-archive-name":
        print(image_tar_name(args.image, archive_suffix(args.like) if args.like else ".tar"))
    elif args.command == "k8s":
        render_k8s(
            args.handler,
            args.pod,
            args.node,
            args.image,
            args.annotations,
            args.out_dir,
            args.run_as_user,
            args.pod_dir,
            parse_device_resources(args.device_resource),
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
