#!/usr/bin/env bash
# Delete the delivery package's test Pod.
#
# Only the Pod goes away. The RuntimeClass and the containerd handler stay:
# they belong to the runtime this package installs and are used by every Pod
# that selects it, not by the test alone.
#
# It waits for the card's vfio group to be released before returning, so a
# create after this script cannot start a VM on a card the deleted one still
# holds. Here a holder that outlives the timeout is only a warning: nothing
# dangerous happens by returning, and the next create repeats the wait.
#
# Usage: sudo bash test/delete-test-pod.sh
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for cmd in kubectl python3 find; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: $cmd is not installed or not in PATH" >&2
    exit 1
  fi
done

# See create-test-pod.sh for why this exists; keep the two copies in step. The
# roots are overridable only so the helper can be tested locally.
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
        echo "warning: /dev/vfio/$group is still open after ${timeout}s (held by $holder)" >&2
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

# The Pod name comes from the package's own manifest. Reading it here rather
# than from a rendered settings block keeps this script to the one thing it
# needs, and a rename cannot silently make it delete another package's Pod.
tmp_pod_name="$(mktemp /tmp/taa-pod.XXXXXX.py)"
trap 'rm -f "$tmp_pod_name"' EXIT
cat > "$tmp_pod_name" <<'TAA_PY'
import json, sys
from pathlib import Path

manifest = Path(sys.argv[1]) / "test" / "test-pod.yaml"
try:
    pod = json.loads(manifest.read_text())
except FileNotFoundError:
    raise SystemExit(f"package is incomplete, missing {manifest}")
except json.JSONDecodeError as exc:
    raise SystemExit(f"{manifest}: not valid JSON ({exc})")
name = pod.get("metadata", {}).get("name", "")
if not name:
    raise SystemExit(f"{manifest}: metadata.name is missing")
print(name)
TAA_PY
if ! TEST_POD_NAME="$(python3 "$tmp_pod_name" "$pkg_dir")"; then
  echo "error: 交付包自校验失败" >&2
  exit 1
fi

if ! kubectl get pod "$TEST_POD_NAME" >/dev/null 2>&1; then
  echo "测试 Pod 不存在，无需删除: $TEST_POD_NAME"
  exit 0
fi

kubectl delete pod "$TEST_POD_NAME" --ignore-not-found --wait=true
wait_dcu_vfio_release || true
echo "已删除测试 Pod: $TEST_POD_NAME"
