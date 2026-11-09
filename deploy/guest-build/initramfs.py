#!/usr/bin/env python3
"""Read a possibly multi-member gzip initramfs without unpacking it.

The build appends TAA as its own gzip member to a precomputed seed image, so a
re-injection only has to compress the few megabytes of TAA instead of the whole
seed (the semgrep payload alone is ~337 MiB and gzip -9 over it costs ~110 s).
The kernel accepts that: gzip concatenation is a stream of independent members,
and Linux's initramfs unpacker reads every member in turn. Verified on the Kata
confidential kernel with a two- and a three-member image.

`cpio -t` does not: it stops at the TRAILER of the first archive, which would
make every entry of the appended member look missing. This helper slices the
file at gzip-member boundaries and asks cpio about each member, so the build's
verification sees what the kernel will see.

Usage:
    initramfs.py list <image>            one entry path per line, all members
    initramfs.py has  <image> <entry>    exit 0 when present, 1 when not
    initramfs.py cat  <image> <entry>    write the entry's contents to stdout
"""

import subprocess
import sys
import zlib

_MAGIC = b"\x1f\x8b"


def members(data):
    """Yield each gzip member's decompressed bytes, in file order."""
    offset = 0
    total = len(data)
    while offset < total:
        if data[offset : offset + 2] != _MAGIC:
            raise SystemExit(
                f"error: not a gzip member at byte {offset} "
                f"(the initrd must be one or more concatenated gzip streams)"
            )
        # MAX_WBITS + 16 asks zlib for the gzip wrapper; unused_data is what
        # follows this member, which is exactly how the next member is found.
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = decompressor.decompress(data[offset:])
        consumed = total - offset - len(decompressor.unused_data)
        if consumed <= 0:
            raise SystemExit(f"error: empty gzip member at byte {offset}")
        yield raw
        offset += consumed


def run_cpio(args, raw):
    result = subprocess.run(
        ["cpio", *args], input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return result


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)

    command, image = argv[1], argv[2]
    entry = argv[3] if len(argv) > 3 else None
    with open(image, "rb") as handle:
        data = handle.read()

    if command == "list":
        for raw in members(data):
            result = run_cpio(["-t", "--quiet"], raw)
            if result.returncode != 0:
                raise SystemExit(
                    "error: cpio could not list a member of "
                    f"{image}: {result.stderr.decode(errors='replace').strip()}"
                )
            sys.stdout.buffer.write(result.stdout)
        return 0

    if command == "has":
        if entry is None:
            raise SystemExit("error: has needs an entry")
        wanted = entry.encode()
        for raw in members(data):
            result = run_cpio(["-t", "--quiet"], raw)
            if result.returncode != 0:
                continue
            if wanted in result.stdout.splitlines():
                return 0
        return 1

    if command == "cat":
        if entry is None:
            raise SystemExit("error: cat needs an entry")
        for raw in members(data):
            result = run_cpio(["-i", "--to-stdout", "--quiet", entry], raw)
            # A member without the entry exits non-zero; the next one may have it.
            if result.returncode == 0 and result.stdout:
                sys.stdout.buffer.write(result.stdout)
                return 0
        return 1

    raise SystemExit(f"error: unknown command: {command}\n{__doc__}")


if __name__ == "__main__":
    sys.exit(main(sys.argv))