# Plan: make the hardware CCP reachable from the CSV2 guest

Date: 2026-11-19
Status: superseded (2026-11-19) — the vCCP route is rejected for TAA because the identity SM2
private key must remain confidential from the host, and the emulated device exposes it. Kept as
the experiment record and for its kernel/initrd findings; the decision and its reasoning are in
`.claude/specs/2026-11-19-hct-ccp-guest-feasibility.md` ("Decision" section). Do not start
Phase 0 for the identity key.

## Why this is possible at all

The vendor's own guest procedure (HCT-3.x `02. 虚拟化部署.md` §2.6 and HCT-2.x
`02. 虚拟化部署.md:160-191`) is:

1. install the HCT package in the guest and build `hct.ko` against the guest kernel
   (`sudo make && sudo make install && sudo modprobe hct`) — the driver is loaded but
   never bound to the vCCP;
2. `modprobe vfio; modprobe vfio-pci; echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode`;
3. `hctconfig start -m vfio-pci` (binds the vCCP functions as `vfio-pci` noiommu);
4. `hct_test`.

The kernel prerequisite is HCT-2.x `01. 主机环境搭建.md:199`:
`CONFIG_VFIO_NOIOMMU` must be enabled. That single symbol is what the Kata CSV kernel
(`config-6.6.0+-153-confidential-csv`) lacks today.

Two facts measured on our stack say the rest of the chain is already in place:

- The patched `/opt/kata/bin/qemu-system-x86_64` presents the vCCP: inside a running
  Kata Pod `/proc/bus/pci/devices` shows four `1d94:1468` functions.
- libhct 3.0.10, once `enable_unsafe_noiommu_mode` is `Y`, takes a path that needs no
  `/dev/hct_share`: mode 2 uses a hugepage-backed shared config, optionally opens
  `/dev/hct_mig`, and drives the device through `/dev/vfio/vfio` +
  `/dev/vfio/noiommu-N` with `VFIO_SET_IOMMU(NOIOMMU_IOMMU)`. The guest `hct.ko` is
  exactly the module that mode expects (`HCT_GUEST` → no mdev, registers
  `hct_noiommu` and `hct_mig`). (Verified by disassembly, addresses in the spec.)

## Phase 0 — decisive experiment (do this first, everything else is only worth doing if it passes)

1. Rebuild the Kata CSV guest kernel from the same source that produced
   `config-6.6.0+-153-confidential-csv`, changing **only**:
   `CONFIG_VFIO_NOIOMMU=y` (and, if they are modules today, keep `CONFIG_VFIO=y`,
   `CONFIG_VFIO_PCI=y` built in so the initrd needs no module loader for them).
   Keep every CSV2 option identical; the kernel hash/MEASUREMENT will change.
2. Build `hct.ko` from the HCT 3.0.10 package against that exact kernel
   (`/opt/hygon/hct/src/module`; the Makefile sets `-DHCT_GUEST` from
   `/proc/cpuinfo` on the build host, so build it inside a hypervisor guest or pass
   `MCFLAGS=-DHCT_GUEST` explicitly).
3. Boot a probe Pod with a QEMU wrapper that adds the four
   `-device hct,dev=/dev/hct/vccpN_{0..3}` options (the wrapper from the earlier
   experiment still works).
4. Inside the guest, by hand:
   - `insmod hct.ko`;
   - mknod the misc nodes from `/proc/misc` (`hct_noiommu`, `hct_mig`, `vfio`) and the
     group nodes from `/sys/class/vfio/*/dev` (`noiommu-N`) — this initrd has **no
     devtmpfs and no udev**, `/dev` is a plain tmpfs, so nothing appears by itself;
   - `echo Y > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode`;
   - bind `0000:00:38.0`, `.1`, `.2`, `.3` (`1d94:1468`) to `vfio-pci` via
     `driver_override` + `bind`;
   - check `/dev/vfio/noiommu-*` appeared and `dmesg` has no vfio warnings;
   - run the vendor `hct_test`, then `taa-hct-helper --accel ccp` selftest.

Exit criteria: `hct_ccp_init` returns 0, the helper reports `sm2=ccp sm3=ccp
hmac-sm3=sw sm4-gcm=ccp`, and the selftest passes. If the hugepage allocation in the
mode-2 path fails, check `CONFIG_HUGETLBFS`/`CONFIG_HUGETLB_PAGE` and reserve 2 MB
pages explicitly; that is the next thing to fix, not a reason to abandon the path.

## Phase 1 — initrd plumbing

All of this belongs in `deploy/guest-build/taa-init.sh`, ordered before TAA starts
(PID 1 cannot wait on anything that needs a restarted init; same rules as the existing
csv-guest mknod):

1. load `hct.ko` (insmod from a path baked into the initrd; ship `kmod` or a static
   insmod, the base initrd for CPU roles has neither module tree nor kmod);
2. create the four misc/group device nodes (helper like `resolve_csv_minor`; never
   hardcode minors);
3. set `enable_unsafe_noiommu_mode=Y` before any bind (or put
   `vfio.enable_unsafe_noiommu_mode=1` in `kernel_params` if vfio is built in);
4. bind each `1d94:1468` function to `vfio-pci` (driver_override + bind loop; log
   every step and continue on failure — TAA must still start and degrade to software);
5. optionally reserve 2 MB hugepages if the probe found libhct does not manage it.

Do **not** ship the vendor `hctconfig` into the initrd just to automate step 4; it
drags in python and is vendor-host oriented. Four shell lines are enough and are
measurable.

## Phase 2 — TAA changes

- `internal/app/taa/crypto_backend.go`: `requireCCPDevice` currently requires
  `/dev/ccp*`, which the vfio route never creates, so `accel=ccp` would silently
  degrade even when the hardware is ready. Extend the gate to accept the vfio route
  (`/dev/vfio/vfio` present and at least one Hygon `1d94:14xx` device bound to
  `vfio-pci`), keeping the existing degradation and its log line for everything else.
  Add a unit test for the three outcomes (ccp node, vfio route, neither) using the
  existing overridable glob.
- Config: `crypto.hct.accel=ccp` in the initrd template; the helper already supports
  it and logs the effective engine map.
- No other code changes: the CCP engine, capability router, sw fallback and logging
  are already committed and tested.

## Phase 3 — packaging and operations

- Kernel image: the runtime class's kernel must point at the rebuilt one
  (`vmlinuz-...-confidential-csv` in `/opt/kata/share/kata-containers/`), and the
  Kata config template (`deploy/guest-build/base/configuration-qemu-csv2.toml`) has
  to keep passing `rdinit=` and the `taa.*` tokens unchanged.
- Attestation: rebuilding the kernel changes the CSV MEASUREMENT. Anything that pins
  the measurement (platform-side provisioning, records) must be re-measured and
  updated; otherwise the deployment breaks in a way that looks unrelated.
- `build-initrd.sh`: add the rebuilt kernel and `hct.ko` to `fetch-base`/render, record
  their SHA-256 in `source-paths.txt` the same way the current base is recorded.

## Validation ladder

1. guest shell: `hct_test` all pass;
2. guest shell: `taa-hct-helper --accel ccp` selftest passes;
3. TAA boot log: `crypto backend: hct (... accel=ccp; engines: sm2=ccp sm3=ccp
   hmac-sm3=sw sm4-gcm=ccp)`;
4. cross-implementation check: data sealed by one backend opens under the other
   (the helper tests already cover this);
5. e2e: an import path that exercises SM2/SM3/SM4-GCM.

## Risks and cost

1. **Security model (the decisive objection).** The vCCP is a QEMU-emulated device:
   the operation, and the key material our helper passes in the SM2 context (the
   private key is memcpy'd into `d_key`), crosses to the host. QEMU holds the guest
   memory keys, and CSV2 has no HOSTDATA/encrypted-device path, so this is not
   protected by the TEE. It contradicts the CSV2 premise "host is untrusted", which
   is why the vendor routes CSV guests to vTKM (`HCT版本说明和阅读指引.md:40`). If
   TAA's identity key must stay hidden from the host, the correct answer is vTKM, not
   this plan.
2. **Kernel fork maintenance.** We do not own the Kata CSV kernel; every Kata/kernel
   upgrade needs the config patch re-applied and the measurement re-baselined.
3. **no-IOMMU is unsafe by design.** Contained by the VM boundary here, but it
   disables vfio's checks; vfio will print the usual "unsafe" warnings.
4. **Guest memory.** The mode-2 path allocates hugepages for shared config/DMA; the
   guest's tmpfs root and Kata memory class must leave room.
5. **No devtmpfs.** Manual mknod is load-bearing and must be tested on every base
   initrd refresh; silent failure leaves TAA on the software engine, which is
   acceptable (degradation contract) but must be visible in the log.

## Alternative if the goal is "hardware crypto in the CSV2 guest", not "hct_ccp specifically"

vTKM: CSV2 is supported with Hygon 3/4 and firmware >= 2131; the host needs the vTKM
kernel/QEMU patches, the VM gets `-device psp,vid=N`, and the guest uses the TKM/SDF
API. This keeps the key operations on hardware the host cannot read, but it is a
different API family from `hct_ccp_*` and would replace TAA's key-operation backend,
not just its transport.
