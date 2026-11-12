#!/usr/bin/env bash
# Delete the delivery package's test Pod.
#
# Only the Pod goes away. The RuntimeClass and the containerd handler stay:
# they belong to the runtime this package installs and are used by every Pod
# that selects it, not by the test alone.
#
# Usage: sudo bash test/delete-test-pod.sh
set -euo pipefail

pkg_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for cmd in kubectl python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: $cmd is not installed or not in PATH" >&2
    exit 1
  fi
done

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
echo "已删除测试 Pod: $TEST_POD_NAME"
