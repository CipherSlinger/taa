#!/usr/bin/env bash
# test-semgrep-payload.sh -- run the built semgrep payload inside the guest
# rootfs, on this machine, with no Hygon host involved.
#
# Why this test exists: the payload is a Python runtime plus a ~300 MiB
# site-packages tree that is copied into an initrd. Every way it can be wrong
# (a missing shared library, a wheel that unpacked into the wrong place,
# semgrep-core without its executable bit, rules not where the config looks)
# would otherwise surface only after a build, an upload, a boot and an audit --
# and the guest's failure mode is a one-line "did not run" in a log nobody is
# watching.
#
# The base initrd *is* the guest rootfs (shared_fs=none, no virtio-fs), so it
# can be unpacked here, the payload laid over it, and the result imported as a
# container image. That is the same filesystem the guest will have, minus the
# kernel.
#
# The same scan then runs in the TAA container arm the rule evidence was
# collected on, and the two finding sets are compared: a payload that starts
# but scans differently is still a wrong answer.
#
# Usage: ./test-semgrep-payload.sh
#
# Environment (all optional):
#   TAA_SEMGREP_PAYLOAD_DIR  $SCRIPT_DIR/semgrep-payload
#   BASE_INITRD              $SCRIPT_DIR/base/kata-containers-initrd-confidential-csv.img
#   ARM_CONTAINER            taa-env-slim-v2 (running TAA container to compare against)
#   KEEP_WORK                1 to keep the work directory for inspection

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PAYLOAD_DIR="${TAA_SEMGREP_PAYLOAD_DIR:-$SCRIPT_DIR/semgrep-payload}"
GUEST_ROOTFS="$PAYLOAD_DIR/rootfs"
BASE_INITRD="${BASE_INITRD:-$SCRIPT_DIR/base/kata-containers-initrd-confidential-csv.img}"
ARM_CONTAINER="${ARM_CONTAINER:-taa-env-slim-v2}"
RULES_IN_GUEST=/opt/taa/semgrep/rules
IMAGE=taa-guest-payload:test

step() { echo "== $*"; }
info() { echo "   $*"; }
die()  { echo "error: $*" >&2; exit 1; }

for cmd in docker gzip cpio tar python3; do
  command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
done
[[ -f "$BASE_INITRD" ]] || die "base initrd not found: $BASE_INITRD (run: build-initrd.sh fetch-base)"
[[ -x "$GUEST_ROOTFS/usr/local/bin/semgrep" ]] || die "payload not built: $GUEST_ROOTFS/usr/local/bin/semgrep missing (run: build-semgrep-payload.sh)"
[[ -x "$GUEST_ROOTFS/opt/taa/semgrep/pylib/semgrep/bin/semgrep-core" ]] || die "payload not built: semgrep-core missing"

WORK_DIR="$(mktemp -d /tmp/taa-semgrep-payload-test.XXXXXX)"
cleanup() {
  docker rmi -f "$IMAGE" >/dev/null 2>&1 || true
  if [[ "${KEEP_WORK:-0}" == "1" ]]; then
    echo "work directory kept: $WORK_DIR"
  else
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

# The sample is the test's own input, so the finding set is a known quantity and
# the two arms are compared on equal footing rather than on whatever a real
# package happens to contain.
step "准备扫描样本"
mkdir -p "$WORK_DIR/sample"
cat >"$WORK_DIR/sample/app.py" <<'SAMPLE'
import os
import subprocess
import socket

API_TOKEN = "AKIAIOSFODNN7EXAMPLE"


def run(user_input):
    os.system("ls " + user_input)
    subprocess.check_output(["bash", "-c", user_input])
    return eval(user_input)


def probe():
    sock = socket.socket()
    return sock.connect(("10.0.0.1", 4444))
SAMPLE

step "解包 base initrd 并叠加 semgrep 载荷"
# The unpacking runs as root inside a container, not as the invoking user: the
# base initrd carries ~250 device nodes under dev/, and a non-root cpio cannot
# create them -- it reports one "Cannot mknod" line each and exits non-zero,
# which under `set -e -o pipefail` would fail this script for a reason that has
# nothing to do with the payload. Alpine is used because its busybox already
# carries cpio; nothing has to be installed to get there.
docker run --rm \
  -v "$BASE_INITRD:/base.img:ro" \
  -v "$GUEST_ROOTFS:/payload:ro" \
  -v "$WORK_DIR:/work" \
  alpine:latest sh -c '
set -e
mkdir -p /work/guest
gzip -dc /base.img | (cd /work/guest && cpio -idm --quiet)
# The payload is laid over the base exactly as build-initrd.sh appends it, so
# this test fails for the same reasons the initrd build would.
cp -a /payload/. /work/guest/
# Hand the tree back to the invoking user: everything after this point -- the
# entry count, the tar for docker import, the cleanup -- runs on the host.
chown -R '"$(id -u):$(id -g)"' /work/guest
' || die "failed to stage the guest rootfs"

# dev/ goes away before the import: the nodes belong to the guest, Docker mounts
# its own /dev over whatever the image has, and a tar carrying device nodes is a
# way to fail `docker import` for no gain.
rm -rf "$WORK_DIR/guest/dev"

step "导入 guest rootfs 为镜像"
info "guest rootfs: $(find "$WORK_DIR/guest" | wc -l) entries"
tar -C "$WORK_DIR/guest" -cf - . | docker import - "$IMAGE" >/dev/null ||
  die "docker import failed"
info "image: $IMAGE"

step "guest rootfs 内运行 semgrep"
version="$(docker run --rm -e HOME=/tmp "$IMAGE" /usr/local/bin/semgrep --version 2>&1)" ||
  die "semgrep --version failed inside the guest rootfs: $version"
info "semgrep --version: $(printf '%s' "$version" | tail -1)"

if ! docker run --rm -e HOME=/tmp -e PATH=/usr/local/bin:/usr/bin:/bin \
    -e SEMGREP_SEND_METRICS=off -v "$WORK_DIR/sample:/sample:ro" "$IMAGE" \
    /usr/local/bin/semgrep scan --config "$RULES_IN_GUEST" --json --quiet \
    --disable-version-check --no-git-ignore --max-memory 1024 /sample \
    >"$WORK_DIR/guest.json" 2>"$WORK_DIR/guest.err"; then
  die "scan failed inside the guest rootfs (stderr: $(tail -3 "$WORK_DIR/guest.err"))"
fi

step "对照臂：运行中的 TAA 容器"
# The container arm's semgrep lives in the container's writable layer, not in
# the image (deploy-docker.sh installs it at deploy time), so the comparison has
# to go through the running container rather than a fresh `docker run`.
arm_ran=0
arm_sample=""
if docker exec "$ARM_CONTAINER" test -x /usr/local/bin/semgrep 2>/dev/null; then
  arm_sample="/tmp/taa-payload-test-sample.$$"
  docker exec "$ARM_CONTAINER" rm -rf "$arm_sample"
  docker cp "$WORK_DIR/sample" "$ARM_CONTAINER:$arm_sample" >/dev/null
  if docker exec -e HOME=/tmp -e SEMGREP_SEND_METRICS=off "$ARM_CONTAINER" \
      semgrep scan --config "$RULES_IN_GUEST" --json --quiet \
      --disable-version-check --no-git-ignore --max-memory 1024 "$arm_sample" \
      >"$WORK_DIR/arm.json" 2>"$WORK_DIR/arm.err"; then
    arm_ran=1
  else
    info "WARNING: scan failed in $ARM_CONTAINER (stderr: $(tail -3 "$WORK_DIR/arm.err"))"
  fi
  docker exec "$ARM_CONTAINER" rm -rf "$arm_sample" || true
else
  info "SKIP: $ARM_CONTAINER is not running or has no semgrep; comparing nothing"
fi

step "比较结果"
# semgrep reports each finding's path as the target was spelled plus the file's
# path under it, and the two arms scan their sample from different directories,
# so the target prefix is stripped before the comparison. The check_id is
# qualified with the rules file's path, which also differs between the arms;
# only the rule's own name is stable, which is how TAA shortens it too.
python3 - "$WORK_DIR/guest.json" "$WORK_DIR/arm.json" "$arm_ran" "/sample" "$arm_sample" <<'PY'
import json
import sys


def findings(path, target):
    with open(path) as fh:
        data = json.load(fh)
    prefix = target.rstrip("/") + "/"
    out = set()
    for r in data.get("results", []):
        rule = r["check_id"].rsplit(".", 1)[-1]
        found = r["path"]
        if target and found.startswith(prefix):
            found = found[len(prefix):]
        out.add((rule, found, r["start"]["line"]))
    return out


guest = findings(sys.argv[1], sys.argv[4])
if not guest:
    sys.exit("FAIL: the guest arm reported no findings at all; the engine ran but found nothing")

if sys.argv[3] != "1":
    print(f"guest arm: {len(guest)} findings, no arm to compare against")
    for rule, path, line in sorted(guest):
        print(f"   {rule} {path}:{line}")
    sys.exit(0)

arm = findings(sys.argv[2], sys.argv[5])
if guest != arm:
    print(f"FAIL: findings differ (guest {len(guest)}, arm {len(arm)})")
    for item in sorted(guest - arm):
        print(f"   guest only: {item}")
    for item in sorted(arm - guest):
        print(f"   arm only:   {item}")
    sys.exit(1)

print(f"identical findings in both arms: {len(guest)}")
for rule, path, line in sorted(guest):
    print(f"   {rule} {path}:{line}")
PY

echo
echo "all checks passed"
