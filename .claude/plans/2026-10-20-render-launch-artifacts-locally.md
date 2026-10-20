# Render launch artifacts locally and ship them as a delivery package

## Context

`deploy/guest-build/build-initrd.sh`'s `launch_remote()` generates the Kata TOML,
the merged containerd config, the RuntimeClass and the test Pod YAML with inline
Python inside a remote SSH heredoc, then applies them on the host. The generated
files exist only on the target host, so handing the flow to another host means
re-running — or hand-rediting — the same generation there.

The goal is to make generation a local, offline, reproducible step and make its
output the delivery package. `launch` keeps working, but as `render locally ->
upload -> install`, so there is one code path and no logic drift.

User decisions already made:
- Delivery package = rendered configs + install script + checksum manifest. The
  ~153 MB initrd / kernel / OVMF are not copied by default.
- `launch` is refactored to the single "local render + upload install" path.

## Design

### 1. Standalone renderer

New tracked file `deploy/guest-build/render/render.py` (Python 3 stdlib only).
Subcommands:

- `kata-config --template T --section S --bundle-dir B --out O`
  Rewrites only the target hypervisor section: comments out `image`, sets
  `kernel`/`initrd`/`firmware` to `B/...`, inserts
  `rdinit=/usr/local/bin/taa-init` at the front of `kernel_params` (dropping any
  stale `init=`/`rdinit=`). Then validates its own output: no active `image`,
  all four keys present, `rdinit=` present. This is the existing inline program
  at `build-initrd.sh:949-1177`, moved.
- `containerd-merge --config C --handler H --runtime-type T --runtime-path P
  --snapshotter S --kata-config K [--out O]`
  Idempotently removes the handler table and its children, then appends the
  canonical handler/options block. Existing inline program at
  `build-initrd.sh:1056-1147`, moved.
- `containerd-strip --config C --handler H`
  The inverse, for tests: a copy of the program currently delimited by
  `# BEGIN containerd-handler-strip` in `deploy-taa-vm.sh:540-599`. `delete`
  keeps its inline copy for this change (see step 5); a test proves the two
  agree by merging and then stripping.
- `k8s --handler H --pod P --node N --image I --annotations JSON --out-dir D`
  Writes `runtimeclass.yaml` and `test-pod.yaml` (JSON is valid YAML). `--node`
  may be empty, in which case `nodeName` is omitted so the package is portable.

### 2. `render` subcommand in `build-initrd.sh`

New settings:

```
KATA_CONFIG_TEMPLATE="${KATA_CONFIG_TEMPLATE:-$SCRIPT_DIR/base/configuration-qemu-csv2.toml}"
DIST_DIR="${DIST_DIR:-$SCRIPT_DIR/dist/$RUNTIME_HANDLER}"
```

`render_package()`:
1. Require `python3`; require the template (hint: `fetch-base`).
2. `rm -rf "$DIST_DIR"` then create it; run `render.py` for the three outputs.
3. Copy the support files (`render/render.py`, `render/install.sh`) into the
   package so it is self-contained.
4. Write `manifest.env` (`KEY=%q`, sourceable) with: handler, runtime type/path,
   snapshotter, bundle dir and its three expected file names, kata config path,
   containerd config path, pod/node/image/annotations, initrd path + sha256 (if
   present), base initrd path + sha256, source template path + sha256,
   `TAA_PLATFORM_IP` / `TAA_DOCKER_ID`, `RESTART_KUBELET`, and the measurement
   inputs `OVMF_SHA256` / `KERNEL_SHA256` / `KERNEL_PARAMS` (from `base/` and the
   rendered config) so the package records what MEASUREMENT is derived from.
5. Write `SHA256SUMS` over every regular file in the package (the same format
   `sha256sum -c` reads; `latti-fhe-handoff/SHA256SUMS` is the precedent).
6. Write a short generated `README.md`: contents, prerequisites, install command,
   usage (`runtimeClassName`), teardown.
7. Print the package path and file list.

No network access; `REMOTE_HOST` is irrelevant to `render`.

### 3. Source Kata template

Extend `fetch_base()` to also pull `REMOTE_KATA_CONFIG_SRC` into
`deploy/guest-build/base/configuration-qemu-csv2.toml` (read-only on the host,
same "host is authority" rule as the base initrd). Add `base/*.toml` and `dist/`
to `deploy/guest-build/.gitignore`.

`launch` calls a small `ensure_kata_template()` before rendering:
- if the local file is missing, fetch it with `scp`;
- compare the local sha256 with the remote file's sha256; refuse on mismatch
  unless `SKIP_REMOTE_KATA_TEMPLATE_CHECK=1`;
- this mirrors the existing base-initrd guard in `deploy_remote()`.

### 4. `install.sh` (tracked at `deploy/guest-build/render/install.sh`)

Reads `manifest.env` next to itself. Steps:

1. Require root or passwordless sudo; require
   `kubectl sudo python3 containerd grep ps`.
2. Verify containerd config is TOML `version = 2`.
3. Guard: target Kata template sha256 must equal the manifest value (override
   `--skip-template-check`); target base initrd sha256 must equal the manifest
   value when the file exists (override `--skip-base-check`).
4. Require `<bundle-dir>/{initramfs.img,vmlinuz,OVMF.fd}`; fail with the
   `deploy` hint otherwise.
5. Install the rendered Kata config to `$REMOTE_KATA_CONFIG`.
6. Merge the containerd handler from the manifest parameters; validate with
   `containerd --config <tmp> config dump`; back up, install, restart, roll back
   on failure; optional kubelet restart.
7. `kubectl apply` the RuntimeClass, delete/recreate the test Pod, wait Ready for
   180 s with status/events on failure.
8. Verify a QEMU process is using `<bundle-dir>/initramfs.img`.
9. Support `--dry-run` (print the actions, no mutation).

### 5. `launch_remote()` refactor

Replace the generation heredoc with:

1. `require_cmd ssh scp python3`.
2. `ensure_kata_template`.
3. Resolve `TEST_NODE_NAME` on the host if empty (existing logic; keep it in a
   small read-only helper so the rendered Pod gets the node).
4. `render_package` into a temp dir (not `DIST_DIR`, to avoid clobbering the
   package the user is preparing) — or `DIST_DIR` when `LAUNCH_KEEP_DIST=1`.
5. `scp -r` the package to a remote `mktemp -d`; run
   `sudo bash <tmp>/install.sh`; trap-clean the temp dir.
6. The package remains on disk locally, so `launch` also leaves the delivery
   artifacts behind.

`delete_remote()` keeps its inline stripper. Moving it would add an upload round
trip to the riskiest path (a shared-host teardown) for no functional gain; the
new `test-render.sh` cross-checks merge-then-strip against the same fixture so
the two implementations cannot silently diverge.

### 6. Driver changes (`deploy-taa-vm.sh`)

- Add `render` to usage and dispatch (`exec "$BUILD_INITRD" render`).
- Add `KATA_CONFIG_TEMPLATE` and `DIST_DIR` to `print-config`.
- `up` unchanged; `launch` now renders as part of its flow.
- Update the CoCo note: the package's Pod YAML carries `cc_init_data` because the
  driver still derives it in `preflight launch`.

## Files

- New: `deploy/guest-build/render/render.py`,
  `deploy/guest-build/render/install.sh`, `deploy/guest-build/test-render.sh`.
- Modify: `deploy/guest-build/build-initrd.sh` (render command, fetch-base,
  launch refactor, print-config), `deploy/guest-build/.gitignore`,
  `deploy-taa-vm.sh` (render dispatch, print-config, delete stripper if deduped),
  `test-deploy-taa-vm.sh` (the `grep -c 'id -u'` == 2 assertion moves: launch's
  check now lives in `install.sh`), `deploy/guest-build/csv2-deploy-command-template.md`.

## Tests (offline)

`deploy/guest-build/test-render.sh` (same plain-bash style as
`test-taa-init.sh`):
- Fixture Kata template; `render` with a temp `DIST_DIR` and a bogus
  `REMOTE_HOST` (must not attempt ssh).
- Assert the rendered Kata config: `image` commented, kernel/initrd/firmware
  point at the bundle, `rdinit=` first in `kernel_params`, other sections intact.
- Assert containerd merge is idempotent (twice = once) and that
  merge-then-strip restores the fixture byte-for-byte (cross-checks the two
  implementations).
- Assert `runtimeclass.yaml` / `test-pod.yaml` parse and carry exactly the
  intended runtimeClass/node/annotations.
- Assert `manifest.env` round-trips through `eval`, `SHA256SUMS` verifies, and
  the package contains the installer + renderer.

Update `test-deploy-taa-vm.sh` for the new dispatch/print-config keys and the
moved sudo check.

## Verification

1. `bash deploy/guest-build/test-render.sh`
2. `./test-deploy-taa-vm.sh`
3. `go test ./...`
4. Offline: `REMOTE_HOST=invalid.invalid ./deploy-taa-vm.sh render` produces the
   package and touches nothing remote.
5. On-host (when available): `./deploy-taa-vm.sh up` still reaches
   `verifiedPass=true`; then `delete --dry-run` shows the same handlers/config
   paths as before.

## Risks

- Template drift between the build host and the target: guarded by sha256, with
  an explicit override.
- Bundle path differences: the rendered TOML contains absolute paths; the
  manifest records them and re-rendering with `REMOTE_BUNDLE_DIR` is the
  documented way to target a different layout.
- Multi-instance collisions: handler, bundle dir and pod name remain
  environment-overridable; the README says to make them unique per delivery.
- Partial failure on the host: the containerd backup/rollback logic moves into
  `install.sh` unchanged.
- The package deliberately excludes the initrd; `install.sh` fails loudly with
  the `deploy` hint when the bundle is missing.
