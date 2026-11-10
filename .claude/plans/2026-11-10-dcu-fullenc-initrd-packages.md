# DCU full-encryption delivery packages for TAA train / infer

## Context

The initrd delivery flow (`deploy-taa-vm.sh` -> `deploy/guest-build/build-initrd.sh`) builds one
package per role: `taa-train`, `taa-infer`, `taa-analysis`. The host has a second guest shape:
the Hygon DCU full-encryption runtime (`configuration-qemu-hygon-dcu-csv2.toml`, handler
`kata-qemu-hygon-dcu-csv2`, kernel `6.6.0-hycu-confidential-csv+`). Two more packages are needed,
`taa-train-dcu` and `taa-infer-dcu` (the request also said `taa-infer-duc`; that spelling is
accepted as an alias and canonicalised).

What makes DCU different, verified on 172.16.10.178:

- The DCU guest kernel is a **different kernel** (`vmlinuz-hycu-confidential-csv.container`,
  release `6.6.0-hycu-confidential-csv+`), so the package must ship it and its modules.
- `hycu.ko` / `hycu-sched.ko` are **out-of-tree modules** (not built into that kernel's config).
  They live only in the DCU guest image's rootfs (`/usr/lib/modules/6.6.0-hycu-confidential-csv+`,
  ~122 MiB, plus `/usr/lib/firmware/6.6.0-hycu-confidential-csv+`, ~5.9 MiB) and `/usr/bin/kmod`.
- The base TAA initrd has **no kmod, no modprobe, no udev, no systemd-modules-load**, so nothing
  will auto-load the driver. The initrd must carry kmod and run `modprobe` explicitly.
- The DCU Kata template uses `image=`, not `initrd=`; `render.py` already comments out `image`
  and emits `initrd` when the template lacks it, and keeps the template's `agent.*` params.
- The DCU test Pod must request the card: `resources.requests/limits hygon.cn/k100_ai: "1"`
  (the device plugin socket `hygon.cn-k100_ai.sock` is present on the host).

## Roles

| | taa-train-dcu | taa-infer-dcu |
|---|---|---|
| CONTRACT_TYPE | 1 | 2 |
| semgrep payload | yes (same gate as `taa-train`) | no |
| runtime handler | `kata-qemu-hygon-dcu-csv2-taa-train` | `kata-qemu-hygon-dcu-csv2-taa-infer` |
| runtime_type | `io.containerd.kata-qemu-hygon-dcu-csv2.v2` | same |
| package dir | `/root/taa-images/package-train-dcu` | `/root/taa-images/package-infer-dcu` |
| test Pod | `test-kata-hygon-dcu-csv2-taa` | `test-kata-hygon-dcu-csv2-taa-infer` |
| test image | `172.16.10.178:31313/vllm:ubuntu-dtk` | same |
| default memory | 20480 MiB | 20480 MiB |
| initrd out | `out/kata-containers-initrd-taa-train-dcu.initrd` (existing `*)` branch) | ...-infer-dcu.initrd |
| kernel modules | `hycu` | `hycu` |
| device resource | `hygon.cn/k100_ai=1` | same |

Default test image is the one the verified DCU Pod on 178 uses. Memory 20480 follows the existing
analysis-role precedent for a ~6.9 GiB image unpack in a tmpfs capped at ~half guest RAM.

## Implementation

### 1. `deploy/guest-build/build-initrd.sh` (main work)

**Role parsing / tables**

- Accept `taa-train-dcu`, `taa-infer-dcu` in the argv scan; map `taa-infer-duc` to `taa-infer-dcu`
  before use so every later function sees one spelling.
- Extend the existing `role_*` functions and add role-derived asset defaults:
  - `role_contract_type`: 1 / 2.
  - `role_wants_semgrep`: `taa-train|taa-train-dcu`.
  - `role_runtime_handler`, `role_package_subdir`, `role_test_pod_name`, `role_test_image`,
    `role_default_memory`, `role_test_pod_run_as_user` (empty).
  - New `role_runtime_type`: `io.containerd.kata-qemu-csv2.v2` for the three existing roles,
    `io.containerd.kata-qemu-hygon-dcu-csv2.v2` for the DCU roles; `RUNTIME_TYPE` default uses it.
  - New `role_kernel_modules` -> `hycu` for DCU, empty otherwise; new `TAA_MODULES` variable
    (env-overridable) feeds `add_kernel_param modules`.
  - New `role_device_resource` -> `hygon.cn/k100_ai=1` for DCU, empty otherwise.
  - New `role_kernel_src` / `role_kata_config_src`: DCU values are
    `/opt/kata/share/kata-containers/vmlinuz-hycu-confidential-csv.container` and
    `/opt/kata/share/defaults/kata-containers/configuration-qemu-hygon-dcu-csv2.toml`.
    `REMOTE_KERNEL_SRC`, `REMOTE_KATA_CONFIG_SRC`, `MEASURE_KERNEL`, `KATA_CONFIG_TEMPLATE`
    default through them, so `fetch-base`, `render` and `measure.py` all follow the role with
    no separate flags.

**DCU payload asset**

- New `DCU_REMOTE_IMAGE` (default the installed
  `/opt/kata/share/kata-containers/kata-containers-2026-10-27-13:31:15.991899743+0000-63f5ac56d-hycu-csv.img`)
  and `DCU_PAYLOAD_DIR` (default `base/dcu-payload`, layout `rootfs/usr/...` + `SOURCE`).
- `fetch_base`: after the four scp's, when the role wants the DCU payload, run an inline remote
  script over `ssh ... bash -s` whose stdout is a `tar --zstd` stream:
  - read partition 1's start with `sfdisk -d` (fallback 6144 sectors), `losetup --read-only`,
    `mount -o ro`, `trap` unmount/detach;
  - resolve the release by listing `usr/lib/modules/` and picking the `*hycu*` entry;
  - stream `usr/lib/modules/<release>`, `usr/lib/firmware/<release>`, `usr/bin/kmod`;
  - local `tar --zstd -xf - -C base/dcu-payload/rootfs`;
  - write `base/dcu-payload/SOURCE` (`release=`, `image=`, `sha256=`).
  All remote progress goes to stderr so it cannot corrupt the archive.
- `.gitignore`: add `base/dcu-payload/`.

**Seed cache**

- `role_wants_dcu_payload`; `dcu_payload_fingerprint` reuses the shape of
  `semgrep_payload_fingerprint` over `$DCU_PAYLOAD_DIR/rootfs`.
- `seed_kind` yields `plain`, `semgrep`, `dcu`, or `semgrep-dcu`.
- `seed_fingerprint`: bump `format=3`, add `dcu_payload=` for the DCU kinds.
- `ensure_seed`: one non-plain branch stages whichever payloads the kind names
  (`stage_semgrep_payload`, new `stage_dcu_payload` = `cp -a rootfs/. stage/`), reuses
  `plan_append_entries` / `write_entries_cpio` unchanged. Payload sizes are logged like the
  semgrep one.
- `check_build_inputs`: for DCU roles require `base/dcu-payload/rootfs/usr/bin/kmod` and
  `.../usr/lib/modules/<release>/modules.dep`, failing with a `fetch-base` hint.
- Extend `stage_taa_config` checks unchanged (DCU train is a semgrep role, infer is regex).

**Render**

- `add_kernel_param modules "$TAA_MODULES"` after the existing eight; the `env.txt` header text
  goes from "8 个键" to 9 and lists `taa.modules`.
- Pass `--device-resource "$(role_device_resource)"` to `render.py k8s` when non-empty.
- Extend `print-config` with `REMOTE_KERNEL_SRC`, `MEASURE_KERNEL`, `TAA_MODULES`,
  `TEST_POD_DEVICE_RESOURCE`, `DCU_PAYLOAD_DIR`.
- Update the usage block with the two roles and a one-line description of the DCU difference.

### 2. `deploy/guest-build/taa-init.sh`

- `cmdline_env_name`: add `modules) echo TAA_MODULES ;;`.
- New `load_kernel_modules`, called between `apply_cmdline_identity` and the `/dev/csv-guest`
  block (module must be loaded before `resolve_csv_minor` is meaningful):
  - no-op when `TAA_MODULES` is empty or `/usr/bin/kmod` is absent;
  - if `/lib/modules/$(uname -r)/modules.dep` is missing, run `/usr/bin/kmod depmod -b /`;
  - for each comma-separated name, `/usr/bin/kmod modprobe <name>`, logging success/failure to
    the console; never fatal (PID 1 must not exit, and TAA has to start regardless).

### 3. `deploy/guest-build/render/render.py`

- `IDENTITY_KEYS` += `modules` (validated like the others: `taa.modules=hycu`).
- `render_k8s(..., device_resources=())`: insert
  `container["resources"] = {"requests": {name: count}, "limits": {name: count}}`.
- CLI: `k8s --device-resource NAME=COUNT` (repeatable, validated).

### 4. `deploy-taa-vm.sh`

- Accept the two roles (and the `taa-infer-duc` alias) in the role case; update header/usage.
- Preflight: when the role is DCU, require the role-derived kernel and `dcu-payload/rootfs` and
  fail with the `fetch-base` hint (values come from the existing `print-config` eval).

### 5. Tests and docs

- `test-deploy-taa-vm.sh`: extend the role alternation assertion; add a `print-config` check for
  `taa-train-dcu` (handler, package dir, memory, `TAA_MODULES=hycu`, device resource).
- `deploy/guest-build/test-render.sh`: extend the role loop with per-role expected
  handler/package-dir mapping (the current `kata-qemu-csv2-${role}` pattern no longer fits);
  add assertions for the DCU handler/runtime_type/memory and for the Pod's device resources.
- `deploy/guest-build/test-taa-init.sh`: whitelist now maps `taa.modules`; add an ordering
  assertion that module loading sits after `apply_cmdline_identity` and before the csv-guest
  block; add a fixture exercising `load_kernel_modules` with a stub `kmod` on PATH.
- `CHANGELOG.md` `### Added` entry; `README.md:505`, `deploy.md:555` and
  `deploy/guest-build/csv2-deploy-command-template.md` role table updated.
- `base/source-paths.txt`: record the DCU kernel/template/image paths and hashes after the first
  real `fetch-base`.

## Known limits (documented in the package README)

- The package supplies the guest side only. DCU full encryption still needs the TEE VBIOS, the
  card bound to `vfio-pci`, host IOMMU, the `cc_init_data` annotation and a DTK-tee container
  image; none of that is done by `install.sh`.
- Loading `hycu` in the initrd is new and unproven until a Pod boots; the log line
  `taa-init: module ...` on the console is the first thing to read if `hy-smi` fails.
- The DCU initrd is roughly 60-70 MiB larger (modules + firmware, compressed); the seed is
  rebuilt once and cached.

## Verification

1. `bash -n` on every touched script; run `test-deploy-taa-vm.sh`, `test-render.sh`,
   `test-taa-init.sh` locally.
2. `build-initrd.sh taa-train-dcu build` (and `taa-infer-dcu`), then
   `python3 initramfs.py has out/... 'usr/lib/modules/6.6.0-hycu-confidential-csv+/updates/dkms/hycu.ko'`
   and the same for `usr/bin/kmod`; confirm the seed cache stamp changed once and is then reused.
3. `build-initrd.sh taa-train-dcu render`: inspect `dist/.../config/kata-config.toml`
   (bundle kernel/initrd, no active `image`, `taa.modules=hycu`, DCU `agent.*` params kept) and
   `test/test-pod.yaml` (`hygon.cn/k100_ai` requests and limits).
4. On 178 (ask before uploading): `fetch-base`, `upload`, `install`, create the test Pod; check
   the console log for `taa-init: module hycu`, then in the guest `lsmod | grep hycu`,
   `uname -r` = `6.6.0-hycu-confidential-csv+`, and `hy-smi`. Finally compare the package's
   predicted MEASUREMENT with the value the platform reports.

## Commit

One commit, Conventional Commits, English, no attribution:
`feat(deploy): add DCU full-encryption initrd delivery packages`.
