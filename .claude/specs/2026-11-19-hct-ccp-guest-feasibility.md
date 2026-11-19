# HCT hardware CCP in the CSV2 guest — feasibility record

Date: 2026-11-19
Status: concluded — not reachable with the shipped Kata CSV kernel, and rejected for TAA on
security grounds (see Decision); software engine stays the operative path, `accel=ccp` remains
implemented and gated.

## Question

Can TAA run its SM2/SM3/SM4 on the Hygon hardware coprocessor (HCT `hct_ccp_*` API) from inside
the CSV2 Kata confidential VM it is deployed in, instead of the `hct_sw_*` software engine?

## What the vendor documents say

- Guest procedure (`docs/c86-devkit/03. 密码技术/02. 用户指南/HCT-3.x 指南/02. 虚拟化部署.md:198-213`):
  install the HCT package in the guest, build and load `hct.ko` ("虚拟机中，hct驱动依然需要加载
  （但无需绑定）"), then
  `Guest中使用HCT套件，vCCP需要绑定为vfio-pci noiommu驱动模式，hctconfig工具会检查虚拟化环境并自动做相应的配置。`
- Requirement for that mode (`HCT-2.x 指南/01. 主机环境搭建.md:199`):
  `（1）确保内核CONFIG_VFIO_NOIOMMU配置为打开状态`.
- Version guidance (`03. 密码技术/HCT版本说明和阅读指引.md:40`): `CSV虚拟机使用TKM` — CSV guests are
  routed to vTKM; no CAE/vCCP procedure exists for them, and no caveat says it is unsupported.

## What was measured on host 172.16.10.178

1. HCT 3.0.10 installed on the host; `hctd` running; vCCPs created
   (`/dev/hct/vccp{0,1}_{0..3}` are regular files created by the daemon, not char devices).
2. The patched QEMU (`/opt/kata/bin/qemu-system-x86_64`, `-device hct,dev=/dev/hct/vccpN_M,help`
   lists `dev`, `sysfsdev`, `vsock-device`, `x-max-bounce-buffer-size`) **does** present the vCCP
   to the guest: inside a running Kata Pod, `/proc/bus/pci/devices` shows four functions
   `1d94:1468` at `00:38`, `00:40`, `00:48`, `00:50` for a sandbox started with
   `-device hct,dev=/dev/hct/vccp0_{0..3}` (this is how the infer-class wrapper was wired).
   The container's `/sys/bus/pci/devices` is filtered and shows only the host bridge — use
   `/proc/bus/pci/devices`.
3. The guest kernel (`/opt/kata/share/kata-containers/config-6.6.0+-153-confidential-csv`, and
   the same config read at runtime through `/proc/config.gz`) has
   `# CONFIG_VFIO_NOIOMMU is not set`; `/sys/module/vfio/parameters/enable_unsafe_noiommu_mode`
   does not exist, so vfio-pci cannot take the vCCP without an IOMMU group.
4. Nothing in the guest provides the accelerator interface libhct needs:
   `/proc/misc` in the guest lists `cpu_dma_latency, vsock, csv-guest, device-mapper, vfio, ...`
   and no `ccp_share`; `grep -i ccp|hygon` over the guest kernel config finds no CCP driver.
   On the host `/dev/ccp_share` is a misc device (10:259) supplied by the kernel `ccp` module
   (417792 bytes, loaded with the vCCPs), not by the HCT package.
5. `hct_ccp_init` opens the accelerator's shared-config node before enumerating devices. Which
   node it opens depends on the detected driver mode (see below): `/dev/ccp_share` when the vCCP
   is seen bound to `vfio-pci`, otherwise `/dev/hct_share`. Running the built helper where such a
   device was visible printed:
   `[error] hct_shared_cfg_init(743): fail to open /dev/ccp_share, errno 2` →
   `[error] hct_ccp_init(307): fail to init ccp` and the helper logged
   `accel ccp unavailable, falling back to sw: hct_ccp_init rc=-1 (no usable CCP device?)`,
   then completed the full selftest on the software engine. In the CSV2 guest neither node exists,
   so the same failure occurs one node name over. This is the intended degradation.
6. Emulated IOMMU as an alternative to the kernel option does not work here. A training-class
   kata-config with `-device intel-iommu,caching-mode=on,device-iotlb=off` plus
   `intel_iommu=on iommu=pt` boots QEMU, but the guest never completes the kata-agent handshake;
   QEMU logs `vtd_process_inv_desc: invalid inv desc: hi=0, lo=0 (unknown type)` and
   `Interrupt Mask set, irq is not generated` (same failure with `intremap=on`).
7. `hct.ko` built against the guest's kernel config (vermagic `6.6.0+ SMP mod_unload`) is a pure
   misc module: it registers `hct_noiommu` and `hct_mig` and pulls in no PCI, DMA or vfio symbol.
   It has no device to drive in this guest. `/dev/hct_noiommu` is not a fallback switch — libhct
   only uses it for page write-back attributes and the SME mask — and neither misc node provides
   the shared-config/DMA channel the CCP path needs.

## How libhct 3.0.10 picks its path (disassembly)

Checked directly against the shipped `libhct.so` (BuildID
`dbf4b5a2a1331cc0d490b5a44e46741c9c6c7756`) to be sure there is no configuration knob we missed:

- **Selection is by probing, not configuration.** `vfio_noiommu_is_enabled` (0x1c4670) opens
  `/sys/module/vfio/parameters/enable_unsafe_noiommu_mode`; `hct_shared_used_driver_mode`
  (0x1a39f0) walks `/sys/bus/pci/drivers/hct` and `/sys/bus/pci/drivers/vfio-pci` for a `0000:*`
  entry whose vendor is `0x1d94` and whose device is one of `1456 1486 14a6 14c6 1468 14b8 14d8`.
  It returns 4 (vfio-pci), 3 (hct driver), 2 (no-IOMMU mode already latched) or 1 (nothing bound).
  `/etc/hct_config` keys and `HCT_*` variables cover logging, sleeps, key sources, CPU affinity
  and `ccp_reserved`; none of them can choose the device interface.
- **Per-device dispatch is by bound driver name** in the table at 0x892bc0:
  `vfio-pci` / `vfio_mdev` / `hct_mdev` → `vfio_setup_device` (0x1c1da0, the VFIO ioctl sequence
  `0x3b64`–`0x3b6a`, with iommu type 8 = NOIOMMU only when the module parameter allows it);
  `ccp-crypto` → `ccp_setup_device` (0xf3570, sysfs BAR mapping plus a 96 MiB
  `/dev/shm/hccp-dma-mem` segment, and it still calls the VFIO DMA-map helper on that route).
  Every branch therefore needs either a working VFIO binding or a kernel driver bound to the vCCP.
- **The shared-config node** is `/dev/ccp_share` when the detected mode is 4, `/dev/hct_share`
  otherwise (0x1a3d04–0x1a3d25). It is used for the version handshake (`ioctl 0xc0204301`,
  op 6, requires ≥ `0.6`) and, through the same ioctl, DMA map/unmap. Nothing in this guest
  registers either name.

## Conclusion

The hardware path is blocked at the kernel boundary, not in TAA:

- the documented vCCP binding needs `CONFIG_VFIO_NOIOMMU`, which the Kata CSV kernel does not
  compile in;
- the only substitute, an emulated vIOMMU, does not survive the CSV/SEV boot;
- no guest-side CCP driver exists to provide `/dev/ccp_share`, and `hct.ko` does not.

Making it work would mean rebuilding the Kata CSV guest kernel with `CONFIG_VFIO_NOIOMMU` (or
fixing the emulated IOMMU under SEV) **and** shipping a guest-side provider for the
`/dev/hct_share` control node (plus a vCCP driver for the `ccp-crypto` route); both are outside
TAA. The vendor does not document CAE/vCCP for CSV guests and routes them to vTKM instead. Until
that changes, `crypto.hct.accel=sw` (libhct CIS/AVX software) or the gmsm `builtin` backend are
the real options; `accel=ccp` is implemented, gated on `/dev/ccp*`, and degrades to software with
the reason logged.

## Decision (2026-11-19): the vCCP route is rejected for TAA

Requirement: TAA's identity SM2 private key must remain confidential from the host.

The vCCP cannot meet it, by construction:

- The device is emulated by QEMU on the host. libhct marshals the private key into its command
  buffers on every operation (`hct_ccp_sm2_gen_keypair` returns it; our bridge memcpy's it into
  `SM2_CCP_PKEY_CTX::d_key`), and QEMU, which holds the CSV memory key, reads those buffers.
  CSV2 has no HOSTDATA or any other encrypted guest-host channel, so the TEE does not cover
  this path.
- The exposure is not limited to the key: SM4 session keys and plaintext/ciphertext sent to
  the vCCP cross the same boundary, so restricting only the key operations to software does
  not fix it.
- Vendor guidance agrees (`03. 密码技术/HCT版本说明和阅读指引.md:40`: `CSV虚拟机使用TKM`).

Consequences:

- `builtin` (gmsm) and `hct_sw` (libhct software) both keep the key in CSV2-encrypted guest
  memory. Neither is more confidential than the other; the choice is performance and
  compatibility.
- `accel=ccp` stays implemented and gated, but has no compliant use in a CSV2 deployment.
- The only vendor path for host-invisible keys is key-isolated vTKM: CSV2 requires Hygon 3/4
  and firmware >= 2131, host kernel vTKM patches, and a QEMU carrying the vTKM patches
  (`-device psp,vid=N -mem2 base=...,size=32M`). libhct 3.0.10 already exports the SDF API
  (`SDF_*`, no separate psp/sdf package). It is not a drop-in transport: keys are used by
  handle and cannot be exported, so the key operations and `DeriveSealingKey`
  (`internal/store/sealed_state.go:107`, derived from the private scalar) would need
  redesign. Whether our host meets the hardware, firmware and kernel requirements has not
  been checked.

## Host state after the experiment

- `kata-config.toml` for the train and infer runtime classes restored from
  `kata-config.toml.bak-iommu` / `.bak-hct` (path back to `/opt/kata/bin/qemu-system-x86_64`,
  original `kernel_params`, `dial_timeout = 90`).
- Probe Pods (`hct-probe`, `hct-probe-iommu`) deleted.
- The `qemu-hct-*.sh` wrappers and `kata-config.toml.bak*` copies are left in
  `/root/taa-images/package-{train,infer}/` as artifacts; they are not referenced by any config.
- HCT 3.0.10 stays installed on the host and `hctd` keeps running (installing it was a goal in
  itself; it is not needed by the CSV2 guest path).
