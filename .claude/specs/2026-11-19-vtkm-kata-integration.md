# vTKM inside a Kata CSV2 pod — integration record

Date: 2026-11-19
Status: kernel blocker cleared and verified end-to-end on 172.16.10.178. A Key-Isolated
vTKM key can be created, used and verified from inside a `kata-qemu-csv2` sandbox. What
remains is rollout (packages, base image, MEASUREMENT re-baseline) and the TAA-side code
change (SDF handles + sealing-key redesign).

Companion records: `2026-11-19-vtkm-csv2-feasibility.md` (plain VM proof),
`2026-11-19-hct-ccp-guest-feasibility.md` (why the vCCP path is rejected).

## Scaffolding (built and validated first)

A throwaway runtime class `kata-qemu-vtkm-test` was assembled in
`/root/taa-images/vtkm-test/` on the host:

- `qemu-vtkm-wrapper.sh` — allocates `hag tkm vtkm_create -mode exclusive`, parses `vid: N`,
  records `pid/vid` in `/run/taa-vtkm/vid-N`, appends `-device psp,vid=N
  -mem2 base=512G,size=32M`, and `vtkm_destroy`s on exit via an EXIT trap. A janitor pass
  at startup destroys vids whose owning pid is gone (a shim can SIGKILL the wrapper when
  sandbox creation fails, so the trap alone is not enough).
- `kata-config.toml` derived from `configuration-qemu-csv2.toml`: `path` → the wrapper,
  `kernel_params += " memmap=32M$512G"` (the `$` must survive Kata's quoting; verified in
  `/proc/cmdline` inside the guest).
- containerd handler + `RuntimeClass` named `kata-qemu-vtkm-test`; the handler mirrors a
  working TAA handler (`runtime_type = io.containerd.kata-qemu-csv2.v2`,
  `privileged_without_host_devices`, `snapshotter = "nydus"`, `options.ConfigPath`).

Observed: pods reach 1/1 Running; the wrapper log shows `allocated vid=N` … `released
vid=N rc=0`; after pod deletion `hag tkm vtkm_all_key_usage` reports
`Used_exclusive_vid_nums: 0` and `/run/taa-vtkm/` is empty.

One sizing gotcha: `default_memory = 2048` in the stock csv2 config is too small to unpack
the 683 MB `taa-env` image through CDH — the pod fails with
`[CDH] Image Pull error: Failed to decode layer data stream: Failed to unpack layer`.
Raising `default_memory` to 10240 fixed it (the working TAA class also runs a larger
guest).

## Kernel source: what the shipped kernel actually is

- The shipped Kata CSV kernel is `6.6.0+` built with Ubuntu gcc 11.4.0. Mainline v6.6 has
  neither `CONFIG_HYGON_CSV` nor `CONFIG_CSV_GUEST`, so it cannot be mainline; it is an
  openEuler/anolis 6.6 tree plus the Kata fragments.
- Source obtained without a vendor tarball: `dnf download --source kernel` on 178 produced
  `kernel-6.6.0-145.0.13.139.oe2403.src.rpm` (84,570,112 B). `rpm2cpio | cpio -id` yields
  `kernel.tar.gz` (237,715,716 B) plus `kernel.spec` and 26 KABI revert patches.
- Extracted tree has `arch/x86/Kconfig:2077 config HYGON_CSV` and
  `drivers/virt/coco/csv-guest/Kconfig config CSV_GUEST` — everything the CSV guest needs.
- The Kata fork checkout used for the build is `/data/root/workspace/CoCo/kata-containers`
  (commit `92cb0cbd9`). Running its `tools/packaging/kernel/build-kernel.sh setup` with
  `-x` over this tree produces a `.config` that differs from the shipped
  `config-6.6.0+-153-confidential-csv` by **113 lines** — the recipe is the same family.

## Kernel rebuild recipe (reproduced)

```
# 1. toolchain (host 178, openEuler 24.03)
dnf install -y elfutils-libelf-devel openssl-devel dwarves ncurses-devel rsync cpio

# 2. stage the tree
mkdir -p /data/build/kernel-src && cd /data/build/kernel-src
rpm2cpio kernel-6.6.0-145.0.13.139.oe2403.src.rpm | cpio -idm
tar xzf kernel.tar.gz -C /data/build/kata-kernel-6.6.0-csv --strip-components=1

# 3. generate the Kata config in place
cd /data/root/workspace/CoCo/kata-containers/tools/packaging/kernel
HYGON_CSV=1 ./build-kernel.sh -a x86_64 -f -x -v 6.6.0 \
    -k /data/build/kata-kernel-6.6.0-csv setup

# 4. the only two deltas from the shipped kernel
cd /data/build/kata-kernel-6.6.0-csv
scripts/config --enable DEVMEM
scripts/config --set-str LOCALVERSION "+"     # reproduce 6.6.0+ so /lib/modules matches
make syncconfig

# 5. build + install
cd /data/root/workspace/CoCo/kata-containers/tools/packaging/kernel
HYGON_CSV=1 ./build-kernel.sh -a x86_64 -x -v 6.6.0 \
    -k /data/build/kata-kernel-6.6.0-csv build
DESTDIR=<staging> HYGON_CSV=1 ./build-kernel.sh -a x86_64 -x -v 6.6.0 \
    -k /data/build/kata-kernel-6.6.0-csv install
```

Result: `bzImage` 7,602,688 B, `vmlinux` 41,315,256 B, one module (`efi_secret.ko`),
release `6.6.0+`, and `CONFIG_DEVMEM=y CONFIG_STRICT_DEVMEM=y CONFIG_HYGON_CSV=y
CONFIG_CSV_GUEST=y CONFIG_AMD_MEM_ENCRYPT=y`.

Why `DEVMEM` and not `STRICT_DEVMEM=n`: the host runs vTKM with `DEVMEM=y` +
`STRICT_DEVMEM=y`. The mem2 window is e820 **reserved** (the `$` in `memmap=32M$512G`
forces reserved; `/proc/iomem` shows `8000000000-8001ffffff : Reserved`), so
`devmem_is_allowed()` permits it even with strict filtering on. Turning strict filtering
off would widen the guest attack surface for no gain.

## Verified inside a Kata pod

Kernel swapped into `kata-config.toml`, pod scheduled with `runtimeClassName:
kata-qemu-vtkm-test`:

- `/proc/config.gz` → `CONFIG_DEVMEM=y`; `uname -r` → `6.6.0+`.
- The container's `/dev` is a per-container tmpfs assembled by the kata agent, so
  `/dev/mem` is absent even with `DEVMEM=y`; `mknod /dev/mem c 1 1` creates it (this only
  matters for test pods — TAA itself runs as the first userspace process in the guest
  initrd, where devtmpfs provides the node).
- `read()`/`pread()` on the window returns `EFAULT`: `xlate_dev_mem_ptr()` goes through
  `memremap()`, which tries the ioremap path on a reserved range. A read inside System RAM
  returns `EPERM` (strict filtering). **Neither is the path libhct uses** — libhct mmaps
  the window (`MAP_SHARED|MAP_FIXED|MAP_POPULATE`).
- mmap probe (same flags minus `MAP_FIXED`):
  `mmap(NULL, 32M, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, /dev/mem, 512G)` returns
  a valid mapping and readable bytes.
- Full SDF flow with the host `hag` binary copied into the pod (plus `libnuma.so.1`):

```
hag tkm dev_info_get            -> api_version 0x10004, fw 2248, chip SRYUY22080405
hag tkm intl_key_gen -type sm4 -idx 10 -password ...        -> key index 0x200000a
hag tkm app_key_gen  -type sm2 -phandle 0x0200000A ... -out sm2.bin   (3112 B)
hag tkm key_import   -phandle 0x0200000A ... -key sm2.bin   -> import handle 0x89000001
hag tkm sm2_sign     -handle 0x89000001 ... -in d.bin -out s.bin      (64 B)
hag tkm pubkey_export -handle 0x89000001 -out p.bin                  (132 B)
hag tkm sm2_verify   -dgst d.bin -pub p.bin -sig s.bin               -> successful
```

Flipping one byte of the digest makes `sm2_verify` fail (`-1`), so the verification is not
vacuous. `hag` is statically linked against libhct but dynamically linked against libnuma;
the test pod needed `/tmp/libnuma.so.1` on `LD_LIBRARY_PATH`.

## Remaining work

1. **Rollout**: put the new `vmlinuz` into `deploy/guest-build/base/` and
   `/root/taa-images/package-{analysis,infer,train,train-dcu}/bundle/`, and into `dist/*`.
   Then re-baseline the CSV MEASUREMENT (kernel is measured).
2. **Initrd check**: confirm `/dev/mem` exists in the TAA initrd boot (devtmpfs) and that
   `TKM_VID`/mem2 is passed on the production QEMU command line — in production the wrapper
   must be the one Kata invokes for every sandbox of the TAA classes, not an extra class.
3. **vid lifecycle in production**: the janitor + EXIT-trap wrapper works but was exercised
   only by hand. Pod stop hooks must guarantee `vtkm_destroy`; a leaked vid is unrecoverable
   without destroy+create, which wipes the key space.
4. **TAA code**: key operations move to SDF handles (private key never in process memory);
   `DeriveSealingKey` (`internal/store/sealed_state.go:107`) cannot derive from the scalar
   any more and must move to the CSV hardware sealing key; the app-key blob and `key_image`
   (both ciphertext) become sealed state and are reloaded at startup
   (`key_image_load` + `key_import`).
5. **Security model unchanged**: the host still controls vid lifecycle and can bind the vid
   to its own VM to *use* the key by handle. It cannot read the key. Strictly better than
   the vCCP path.
