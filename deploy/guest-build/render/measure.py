#!/usr/bin/env python3
"""CSV2 launch-digest helper for the TAA delivery package.

Subcommands:

  cmdline  Rebuild the QEMU -append string Kata will use for a rendered config.
  digest   Compute CSV2 MEASUREMENT = SM3(OVMF || hashes-table), where the
           hashes table holds SHA256(cmdline), SHA256(initrd), SHA256(kernel).

The vendor tool /opt/hygon/csv/confidential-containers/scripts/csv-measure.py
does the same thing, but it needs pysmx and the exact QEMU append. This copy is
stdlib-only (pure-Python SM3), so a package recipient can recompute the value on
the target host, and `render` can compute it offline.

cmdline input files are newline-terminated: like the vendor tool, the trailing
newline is replaced by a NUL before hashing. A file without the newline is
rejected instead of silently dropping its last byte.
"""

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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
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


if __name__ == "__main__":
    sys.exit(main())
