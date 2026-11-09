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

# package-info also refuses a moved package, so a rename cannot silently make
# this script delete a Pod that belongs to another package.
if ! pkg_settings="$(python3 "$pkg_dir/render.py" package-info --dir "$pkg_dir")"; then
  echo "error: 交付包自校验失败" >&2
  exit 1
fi
eval "$pkg_settings"

if ! kubectl get pod "$TEST_POD_NAME" >/dev/null 2>&1; then
  echo "测试 Pod 不存在，无需删除: $TEST_POD_NAME"
  exit 0
fi

kubectl delete pod "$TEST_POD_NAME" --ignore-not-found --wait=true
echo "已删除测试 Pod: $TEST_POD_NAME"
