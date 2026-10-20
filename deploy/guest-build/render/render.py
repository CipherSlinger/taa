#!/usr/bin/env python3
"""Render the on-host artifacts of the TAA-in-initrd flow.

Generation runs on the build host so the same files can be installed by
`launch` and shipped as a delivery package. Stdlib only; nothing here touches
the network or the target host.
"""

import argparse
import json
import re
import shlex
import sys
from pathlib import Path

RDINIT = "rdinit=/usr/local/bin/taa-init"


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


def render_kata_config(template, section, bundle_dir, out):
    """Point one hypervisor section at the TAA bundle; leave everything else."""
    path = Path(template)
    lines = path.read_text().splitlines()
    out_lines = []
    seen = {"kernel": False, "initrd": False, "firmware": False, "kernel_params": False}
    in_target = False
    target_seen = False

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
            out_lines.append(f'kernel_params = {toml_string(RDINIT)}')
            seen["kernel_params"] = True

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
            out_lines.append(f'kernel_params = {toml_string(" ".join(params))}')
            seen["kernel_params"] = True
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
    target = containerd_target(handler)
    out_lines = []
    skip = False
    for line in Path(config).read_text().splitlines():
        parts = table_path(line)
        if parts is not None:
            skip = is_target_or_child(parts, target)
            if skip:
                continue
        if not skip:
            out_lines.append(line)
    while out_lines and not out_lines[-1].strip():
        out_lines.pop()
    Path(config).write_text("\n".join(out_lines) + "\n")


def render_k8s(handler, pod_name, node_name, image, annotations_json, out_dir):
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
    pod_spec = {
        "runtimeClassName": handler,
        "restartPolicy": "Never",
        "containers": [
            {
                "name": "test",
                "image": image,
                "command": ["sh", "-c", "echo hello from kata csv2 taa guest; sleep 3600"],
            }
        ],
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
    (out / "test-pod.yaml").write_text(json.dumps(pod, indent=2) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    kata = sub.add_parser("kata-config", help="rewrite one Kata hypervisor section")
    kata.add_argument("--template", required=True)
    kata.add_argument("--section", required=True)
    kata.add_argument("--bundle-dir", required=True)
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

    k8s = sub.add_parser("k8s", help="write RuntimeClass and test Pod manifests")
    k8s.add_argument("--handler", required=True)
    k8s.add_argument("--pod", required=True)
    k8s.add_argument("--node", default="")
    k8s.add_argument("--image", required=True)
    k8s.add_argument("--annotations", default="{}")
    k8s.add_argument("--out-dir", required=True)

    args = parser.parse_args(argv)

    if args.command == "kata-config":
        render_kata_config(args.template, args.section, args.bundle_dir, args.out)
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
    elif args.command == "k8s":
        render_k8s(args.handler, args.pod, args.node, args.image, args.annotations, args.out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
