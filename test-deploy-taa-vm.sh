#!/usr/bin/env bash
# Offline tests for deploy-taa-vm.sh.
#
# The driver is one fixed sequence -- compile TAA, build the initrd, render the
# package, upload it whole -- with no subcommands, so what can be exercised
# without a host is the defaults it supplies, the order of the preflight, the
# compile-before-inject rule and the argv surface. Everything that talks to the
# host lives in build-initrd.sh; its rendering is covered by test-render.sh.
#
#   ./test-deploy-taa-vm.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIVER="$SCRIPT_DIR/deploy-taa-vm.sh"
# The driver owns the flow; build-initrd.sh owns the defaults it resolves.
BUILD="$SCRIPT_DIR/deploy/guest-build/build-initrd.sh"

tmp_dir="$(mktemp -d /tmp/test-deploy-taa-vm.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT

failures=0
check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    failures=$((failures + 1))
  fi
}

check_contains() {
  local name="$1" needle="$2" haystack="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name (missing: $needle)" >&2
    failures=$((failures + 1))
  fi
}

# ── 1. the resolved defaults the driver consumes ─────────────────────────────
#
# build-initrd.sh remains the authority and still exposes print-config as its
# internal interface; the driver evals it, so this is the same view the flow
# sees. The driver's own defaults are read as source text, since a bare run
# needs a host.
driver_src="$(cat "$DRIVER")"
config="$(REMOTE_USER=root TEST_POD_ANNOTATIONS='{"a.b":"c d"}' "$BUILD" print-config)"
eval "$config"
check "print-config: REMOTE_USER override survives" "root" "$REMOTE_USER"
check "print-config: JSON with a space survives eval" '{"a.b":"c d"}' "$TEST_POD_ANNOTATIONS"

default_config="$("$BUILD" print-config)"
eval "$default_config"
check "print-config: default annotations are an empty object" "{}" "$TEST_POD_ANNOTATIONS"
check "print-config: default handler" "kata-qemu-csv2-taa-train" "$RUNTIME_HANDLER"

# Guest RAM is a runtime floor, not a tuning knob: a CSV2 guest's writable root
# is a tmpfs at about half of it and CDH unpacks the image there. 2048 (the base
# template's value) fails the pull for both images, so the default has to come
# from the role. Assert the ordering and the analysis floor, not the exact MiB,
# which is free to grow when an image does.
check "print-config: train guest RAM clears the base template" "yes" \
  "$([[ "${KATA_DEFAULT_MEMORY:-0}" -gt 2048 ]] && echo yes || echo no)"
analysis_memory="$(TAA_ROLE=taa-analysis "$BUILD" print-config |
  sed -n 's/^KATA_DEFAULT_MEMORY=//p' | tr -d "'")"
check "print-config: the analysis image gets a larger guest" "yes" \
  "$([[ "${analysis_memory:-0}" -gt "${KATA_DEFAULT_MEMORY:-0}" ]] && echo yes || echo no)"
# A DCU role differs from its CPU counterpart in four things the flow acts on:
# the handler it installs, the runtime_type it layers on, the kernel module the
# guest loads and the device the test Pod requests. They are all role defaults,
# so assert them through print-config exactly as the driver reads them.
dcu_config="$(REMOTE_HOST=invalid.invalid TAA_ROLE=taa-train-dcu "$BUILD" print-config)"
check "print-config: DCU handler" "kata-qemu-hygon-dcu-csv2-taa-train" \
  "$(sed -n 's/^RUNTIME_HANDLER=//p' <<<"$dcu_config" | tr -d "'")"
check "print-config: DCU layers on the DCU runtime class" "io.containerd.kata-qemu-hygon-dcu-csv2.v2" \
  "$(sed -n 's/^RUNTIME_TYPE=//p' <<<"$dcu_config" | tr -d "'")"
check "print-config: DCU has its own package directory" "/root/taa-images/package-train-dcu" \
  "$(sed -n 's/^REMOTE_PACKAGE_DIR=//p' <<<"$dcu_config" | tr -d "'")"
check "print-config: DCU names the hycu module" "hycu" \
  "$(sed -n 's/^TAA_MODULES=//p' <<<"$dcu_config" | tr -d "'")"
check "print-config: DCU Pod requests the card" "hygon.cn/k100_ai=1" \
  "$(sed -n 's/^TEST_POD_DEVICE_RESOURCE=//p' <<<"$dcu_config" | tr -d "'")"
# The template's local name follows the remote one, as the kernel's does. A
# fixed name here made render compare the CPU template with the DCU one and
# fail after the initrd had already been built.
check "print-config: the DCU template follows the role" "configuration-qemu-hygon-dcu-csv2.toml" \
  "$(basename "$(sed -n 's/^KATA_CONFIG_TEMPLATE=//p' <<<"$dcu_config" | tr -d "'")")"
check "print-config: the CPU template keeps its own name" "configuration-qemu-csv2.toml" \
  "$(basename "$(sed -n 's/^KATA_CONFIG_TEMPLATE=//p' <<<"$default_config" | tr -d "'")")"
# The CPU roles must stay empty here: a module list on them would make taa-init
# look for a kmod binary their initrd does not ship.
check "print-config: a CPU role loads no modules" "" \
  "$(sed -n 's/^TAA_MODULES=//p' <<<"$default_config" | tr -d "'")"

check_contains "print-config: exposes the Kata config template" "KATA_CONFIG_TEMPLATE=" "$default_config"
check_contains "print-config: exposes the delivery package directory" "DIST_DIR=" "$default_config"
# The upload writes through sudo on the far side, so the default account has to
# be one that can. A non-root default needs NOPASSWD sudo set up first, which is
# exactly the failure this default avoids.
check "print-config: default remote user is root" "root" "$REMOTE_USER"

# The guest pulls the image itself and has no route to Docker Hub (measured),
# so the default must name a registry on the host. Assert that property rather
# than the literal image, which is free to change.
case "$TEST_IMAGE" in
  "$REMOTE_HOST":*) echo "ok   print-config: default test image is served by the host itself ($TEST_IMAGE)" ;;
  *) echo "FAIL print-config: default test image is not host-local: $TEST_IMAGE" >&2
     failures=$((failures + 1)) ;;
esac

# The whole flow lands under one host directory, and the guest bundle is inside
# the package -- derived from REMOTE_PACKAGE_DIR, not separately configurable --
# because the Kata config names those in-package files.
check_contains "driver: default install root" 'TAA_IMAGES_DIR="${TAA_IMAGES_DIR:-/root/taa-images}"' "$driver_src"
check "print-config: package lives under the install root" "/root/taa-images/package-train" "$REMOTE_PACKAGE_DIR"
check "print-config: bundle lives inside the package" \
  "$REMOTE_PACKAGE_DIR/bundle" "$REMOTE_BUNDLE_DIR"
# The handler's ConfigPath points at the packaged copy, so a normal run installs
# no second Kata config under /etc. The package persists, which is exactly what
# REMOTE_PACKAGE_DIR means here.
check "print-config: Kata config is the packaged copy" \
  "$REMOTE_PACKAGE_DIR/config/kata-config.toml" "$REMOTE_KATA_CONFIG"

# ── 1b. the identity defaults the driver supplies ────────────────────────────
#
# A bare run is meant to work, so the platform address, docker id and LLM
# endpoint have defaults rather than a remembered environment. These are plain
# assignments at the top of the driver; the flow itself needs a host, so they
# are checked as source text.
check_contains "driver: default platform port" 'PLATFORM_PORT="${PLATFORM_PORT:-18081}"' "$driver_src"
check_contains "driver: platform address is the test platform" \
  'TAA_PLATFORM_IP="${TAA_PLATFORM_IP:-172.16.10.178:${PLATFORM_PORT}}"' "$driver_src"
check_contains "driver: ships a docker id" \
  'TAA_DOCKER_ID="${TAA_DOCKER_ID:-kata-csv2-taa-test-0001}"' "$driver_src"
# The Tier-2 gateway is part of the guest's environment, not the Pod's, so the
# driver has to supply it; leaving it to the template would bake a stale Pod IP.
check_contains "driver: supplies the LLM endpoint" \
  'TAA_LLM_ENDPOINT="${TAA_LLM_ENDPOINT:-https://172.16.10.178:18443}"' "$driver_src"
# The platform public key is read from the platform itself, over the address the
# guest will register against, so the package can never carry a key that
# platform cannot decrypt. The override path keeps offline builds possible.
check_contains "driver: platform key is read from the platform" \
  'PLATFORM_KEY_ENDPOINT="${PLATFORM_KEY_ENDPOINT:-http://${TAA_PLATFORM_IP}/api/crypto/generate-key}"' "$driver_src"
check_contains "driver: an explicit key wins over the fetch" \
  'if [[ -n "${PLATFORM_PUBLIC_KEY:-}" || -n "${TAA_PLATFORM_PUBLIC_KEY:-}" ]]; then' "$driver_src"
check_contains "driver: the fetched key is exported to the build" \
  'export PLATFORM_PUBLIC_KEY' "$driver_src"
# The identity reaches build-initrd.sh as a child process; an unexported
# default would look right here and still build an initrd with no identity.
check_contains "driver: the identity is exported to the build" \
  'export TAA_PLATFORM_IP TAA_DOCKER_ID TAA_LLM_ENDPOINT' "$driver_src"
# The per-role leaf (`package-train`, `package-infer`, ...) belongs to build-initrd.sh,
# which owns the role mapping; the driver only passes the root and any explicit
# override through, so one role can never install over another's package.
check_contains "driver: the install root is exported to the build" 'export TAA_IMAGES_DIR' "$driver_src"
check_contains "driver: an explicit package dir is exported" 'export REMOTE_PACKAGE_DIR' "$driver_src"
if [[ "$driver_src" == *'$TAA_IMAGES_DIR/package"'* ]]; then
  echo "FAIL driver: the package leaf is duplicated in the driver" >&2
  failures=$((failures + 1))
else
  echo "ok   driver: the package leaf lives only in build-initrd.sh"
fi

# ── 2. one behaviour, no subcommands ────────────────────────────────────────
#
# The driver used to dispatch up/push/build/launch/upload/fetch-base/render/
# verify/delete/print-config. What remains is the push sequence and nothing
# else; a re-added subcommand would show up as an argv case.
#
# The one argument it takes is the role, and it is a selection rather than a
# subcommand: it changes what is packaged, not which sequence runs.
check_contains "driver: accepts the CPU and DCU roles" 'taa-train|taa-infer|taa-analysis|taa-train-dcu|taa-infer-dcu)' "$driver_src"
check_contains "driver: canonicalises the taa-infer-duc spelling" 'taa-infer-duc) export TAA_ROLE=taa-infer-dcu' "$driver_src"
check_contains "driver: hands the role to build-initrd.sh" 'export TAA_ROLE="$1"' "$driver_src"
check_contains "driver: refuses an unknown role" 'unknown role or argument' "$driver_src"
check_contains "driver: supports --help" '--help) usage; exit 0' "$driver_src"
for removed in 'up)' 'push)' 'verify)' 'delete)' 'print-config)'; do
  if [[ "$driver_src" == *"  $removed"* ]]; then
    echo "FAIL driver: the '$removed' command is back" >&2
    failures=$((failures + 1))
  else
    echo "ok   driver: no '$removed' command"
  fi
done

# The sequence: preflight, then build, then upload, and nothing is installed.
check_contains "driver: builds the initrd" '"$BUILD_INITRD" build' "$driver_src"
check_contains "driver: goes through the upload step" '"$BUILD_INITRD" upload' "$driver_src"
check_contains "driver: stops before installing" '=== 3/3 未安装 ===' "$driver_src"
check_contains "driver: hands over the install command" 'sudo bash install.sh' "$driver_src"

# The initrd carries whatever bin/taa holds, so the driver has to compile before
# injecting; otherwise a forgotten rebuild ships the previous revision silently.
check_contains "build: recompiles TAA before injecting it" 'CGO_ENABLED=0 GOOS=linux go build' "$driver_src"
check_contains "build: a failed compile leaves the old binary untouched" 'TAA 编译失败，未改动' "$driver_src"
check_contains "build: the recompile can be skipped explicitly" 'TAA_SKIP_GO_BUILD' "$driver_src"
check_contains "build: an overridden TAA_SRC is not recompiled" '跳过重新编译' "$driver_src"
check_contains "build: checks the binary is statically linked" 'statically linked' "$driver_src"

# The upload performs the only host-side write, and it needs passwordless sudo;
# the check lives here so the run fails before a build rather than after one.
check_contains "preflight: checks passwordless sudo" 'NOPASSWD sudoers' "$driver_src"
check_contains "preflight: checks the base initrd first" 'base initrd 缺失' "$driver_src"

# ── 3. build-initrd.sh invariants the flow depends on ───────────────────────
build_src="$(cat "$BUILD")"
# The initrd and the production Pod run one template now; a second template was
# a copy that could drift without either side noticing.
check_contains "build-initrd.sh: the initrd runs the production template" 'configs/taa-production.json' "$build_src"
if [[ -e "$SCRIPT_DIR/configs/taa-initrd.json" ]]; then
  echo "FAIL configs/taa-initrd.json still exists" >&2
  failures=$((failures + 1))
else
  echo "ok   configs/taa-initrd.json is gone"
fi

# TAA exits without the platform key, and the guest has no other injection path,
# so the build must resolve it and write it into the measured env file.
check_contains "build-initrd.sh: reads the platform key from the mock state file" 'publicKeyHex' "$build_src"
check_contains "build-initrd.sh: validates the platform key wire format" '^04[[:xdigit:]]{128}$' "$build_src"
check_contains "build-initrd.sh: bakes the platform key into taa.env" "export PLATFORM_PUBLIC_KEY=" "$build_src"
check_contains "build-initrd.sh: bakes the LLM endpoint into taa.env" "export TAA_LLM_ENDPOINT=" "$build_src"
check_contains "build-initrd.sh: compares the baked platform key" '烘焙的平台公钥与本次调用不一致' "$build_src"

# The interpreter is the payload's business, including the python/python3 names
# model runtimeConfig commands use: they ship next to the interpreter, so the
# plain seed (no Python) cannot end up with dangling links. The build only has to
# refuse a payload whose interpreter is missing.
check_contains "build-initrd.sh: requires the payload interpreter" \
  '"rootfs/usr/local/bin/python3.12" \' "$build_src"

# build-initrd.sh has no mutating remote step left: upload only places files and
# install.sh does every host-side write. The privilege precheck therefore lives
# in install.sh, in the one place that still touches the host.
install_src="$(cat "$SCRIPT_DIR/deploy/guest-build/render/install.sh")"
# grep -c exits 1 on a zero count, which `set -e` would turn into a failed test
# run instead of the assertion it is here to make.
sudo_checks="$(grep -c 'id -u' "$BUILD" || true)"
check "build-initrd.sh: no remaining host-side mutation step" "0" "$sudo_checks"
sudo_checks="$(grep -c 'id -u' <<<"$install_src" || true)"
check "install.sh: sudo precheck for install" "1" "$sudo_checks"
check_contains "install.sh: the precheck explains the hint" 'NOPASSWD sudoers' "$install_src"

# The Kata config ships inside the package and the handler references it in
# place, so install.sh never copies it: it derives the ConfigPath from the
# package and refuses a package whose paths resolve elsewhere.
check_contains "install.sh: derives the ConfigPath from the package" 'package-info --dir' "$install_src"
# grep -c exits 1 on a zero count, which `set -e` would turn into a failed test
# run instead of the assertion it is here to make.
kata_installs="$(grep -cF 'install -o root -g root -m 0644 "$package_kata_config" "$REMOTE_KATA_CONFIG"' \
  <<<"$install_src" || true)"
check "install.sh: installs nothing under /etc for the Kata config" "0" "$kata_installs"

# upload renders and uploads; the install happens in launch, one function away.
# The hint it prints names install.sh, so the assertion is on the invocation
# (`sudo bash ...$package_dir/install.sh`), which lives in launch's heredoc.
check_contains "build-initrd.sh: upload is its own command" 'upload_remote' "$build_src"
check_contains "build-initrd.sh: upload hands over the install command" '尚未安装' "$build_src"
upload_body="$(sed -n '/^upload_remote() {/,/^}/p' "$BUILD")"
if [[ "$upload_body" == *"REMOTE_INSTALL"* || "$upload_body" == *'sudo bash "$package_dir/install.sh"'* ]]; then
  echo "FAIL build-initrd.sh: upload runs install.sh" >&2
  failures=$((failures + 1))
else
  echo "ok   build-initrd.sh: upload never runs install.sh"
fi

# ── 4. argv handling ────────────────────────────────────────────────────────
"$DRIVER" --help >/dev/null 2>&1 && echo "ok   --help exits 0" ||
  { echo "FAIL --help did not exit 0" >&2; failures=$((failures + 1)); }
"$DRIVER" bogus >/dev/null 2>&1 && { echo "FAIL an argument exited 0" >&2; failures=$((failures + 1)); } ||
  echo "ok   an argument exits non-zero"
"$DRIVER" delete >/dev/null 2>&1 && { echo "FAIL 'delete' was accepted" >&2; failures=$((failures + 1)); } ||
  echo "ok   the old 'delete' command is rejected"

# ── 5. preflight refuses before touching the host ───────────────────────────
#
# A missing base must be caught here, with the hint, and without an ssh attempt:
# the base check runs before the privilege check.
out="$(BASE_INITRD="$tmp_dir/absent.img" "$DRIVER" 2>&1 || true)"
check_contains "preflight: explains a missing base initrd" "fetch-base" "$out"
check_contains "preflight: names the missing base before any ssh" "base initrd 缺失" "$out"

mkdir -p "$tmp_dir/fake-tree/bin"
cp /bin/true "$tmp_dir/fake-tree/bin/taa"
out="$(TAA_SRC="$tmp_dir/fake-tree/bin/taa" BASE_INITRD="$tmp_dir/absent.img" "$DRIVER" 2>&1 || true)"
check_contains "preflight: still fails on the missing base first" "base initrd 缺失" "$out"

echo
if [[ "$failures" -eq 0 ]]; then
  echo "all checks passed"
else
  echo "$failures check(s) failed" >&2
  exit 1
fi
