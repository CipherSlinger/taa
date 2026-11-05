#!/usr/bin/env bash
# ensure_go_compiler settles on one toolchain for the whole run. `create` builds the daemon
# twice -- once into the image, once to verify what the Pod carries -- and compares the two files
# byte for byte, so a second call that prepended another installed Go produced two different
# binaries from one tree and failed a correct image at its own verification.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fn="$(awk '/^ensure_go_compiler\(\) \{/,/^\}$/' "$ROOT_DIR/deploy.sh")"
[[ -n "$fn" ]] || { echo "FAIL: ensure_go_compiler not found in deploy.sh" >&2; exit 1; }

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

command -v go >/dev/null 2>&1 || { echo "SKIP: no Go compiler on this host"; exit 0; }

# The function only chooses among the installations the host has; on a host with one of them the
# second call is harmless, and on a host with both the old code switched between them.
export PROJECT_DIR="$TMP_DIR" # no go.mod, so the version check below is skipped
err() { echo "ERROR: $*" >&2; exit 1; }
warn() { :; }

eval "$fn"

ensure_go_compiler
first_go="$(command -v go)"
first_path="$PATH"

ensure_go_compiler
[[ "$(command -v go)" == "$first_go" ]] \
  || fail "the second call switched the compiler from $first_go to $(command -v go)"
[[ "$PATH" == "$first_path" ]] || fail "the second call changed PATH"

echo "PASS: ensure_go_compiler keeps one compiler per run"
