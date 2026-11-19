# Key-isolated vTKM on CSV2 — feasibility record

Date: 2026-11-19
Status: concluded — vTKM works end-to-end in a plain CSV2 VM on host 172.16.10.178, and an
identity key can be carried across VM restarts. Not yet integrated into Kata or TAA; the
blockers are listed below. Companion to `2026-11-19-hct-ccp-guest-feasibility.md`, which
rejects the emulated vCCP because it exposes the private key to the host.

## Question

TAA's identity SM2 private key must remain confidential from the host. Is key-isolated vTKM a
viable hardware-held alternative on this stack — i.e. can a CSV2 guest create, use and later
recover an SM2 key that never exists in host-readable memory?

## Host prerequisites, verified on 172.16.10.178

| item | value |
|---|---|
| CPU | Hygon C86 5380 (海光 C86-3G, family 0x18 model 2) |
| OS / kernel | openEuler 24.03, 6.6.0-145.0.13.139.oe2403.x86_64 |
| vTKM code | in the `ccp` module (`drivers/crypto/ccp/ccp.ko.xz`, sources `hygon/vpsp.c` etc.) |
| firmware / CSV API | 2248 (requirement is >= 2131) |
| `hag` / HCT | 2372 / 3.0.10 |
| TKM | enabled and initialised; `/dev/hygon_psp_config` 10:262, `/dev/hygon_psp_resource2` 10:263 |
| QEMU | the patched `/usr/bin/qemu-system-x86_64` 6.2.0 accepts `-device psp,vid=N` and `-mem2` |
| CSV3 | disabled on this host (not needed for vTKM; CSV2 is supported) |

Vendor reference: `docs/c86-devkit/03. 密码技术/02. 用户指南/通用指南/01. TKM虚拟化补充.md` §2.2
(CSV1/2), §2.5 (teardown). The bare-container `TKM_VID` path in `HCT-3.x 指南/03. 容器化部署.md`
requires `hag >= 2404`; it is **not** our path — TAA runs in a VM, and libhct 3.0.10 already
carries the SDF/vTKM client.

## VM recipe (works, reproducible)

Host:

```
sudo hag tkm vtkm_create -mode exclusive       # prints "vid: N"
qemu-system-x86_64 ... \
  -device psp,vid=N -mem2 base=512G,size=32M \
  ... -object sev-guest,policy=0x5,... -machine memory-encryption=sev0
```

Guest kernel cmdline must contain, literally:

```
memmap=32M$512G
```

The `$` is load-bearing. libhct decides between two hypercall paths in `is_mem2_mode()`
(`libhct.so` 0x221e40): it parses `/proc/cmdline`, and `check_memmap_valid` requires a `'$'`
(0x24) inside the `memmap=` token. With `memmap=32M!512G` the guest falls back to
`psp_do_guest_cmd_copy_forward` (hypercalls 0x65/0x66), and KVM refuses those for a CSV guest:
`kvm_pv_psp_copy_forward_op` checks `kvm_vpsp.is_csv_guest` (offset 0x24) and returns with
`vpsp: [check_cmd_copy_forward_op_permission]: unsupported run on csv guest`; the tool then
reports `__psp_do_guest_cmd[init] failed ret: -1000` (-1000 is `kvm_hygon_arch_hypercall`'s
"unknown hypercall"). With the `$`, libhct uses `psp_do_guest_cmd_forward` → hypercall **0x67**
(`kvm_pv_psp_forward_op`), which *does* have a CSV branch: it validates the GPA inside the
`-mem2` window and issues the PSP command host-side. That path is also why libhct needs
`/dev/mem` to map the window (`map_mem2_memory`, MAP_SHARED|MAP_FIXED|MAP_POPULATE).

## Verified in-guest operations

Verified inside a stock openEuler guest booted under a CSV2 VM (no Kata), `hag` 2372 copied by
hand (the guest has no package manager access to the HCT packages):

```
hag tkm dev_info_get                                  # api_version 0x10004, fw 2248, chip SRYUY22080405
hag tkm intl_key_gen -type sm4 -idx 10 -password 87654321      # -> key index 0x200000a
hag tkm app_key_gen  -type sm2 -phandle 0x0200000A -password 87654321 -out sm2.bin   # 3112 bytes
hag tkm key_import   -phandle 0x0200000A -password1 87654321 -key sm2.bin -password2 12345678
                                                       # -> import handle 0x89000001
hag tkm sm2_sign     -handle 0x89000001 -password 12345678 -in d.bin -out s.bin
hag tkm pubkey_export -handle 0x89000001 -out p.bin   # 132 bytes
hag tkm sm2_verify   -dgst d.bin -pub p.bin -sig s.bin
```

All succeeded; the signature verifies. `sm4`/`sm2_sign` with the internal KEK handle
(`0x0200000A`) and an internal SM2 sign key (`0x0A000001`, created with
`intl_key_gen -type sm2sign -idx 1`) work as well, so the guest can use hardware keys without
any application key at all.

Handle encoding is `type[31:24] | index[23:0]` — `0x02` = KEK_SM4, `0x89` = APP_KEY_SM2. The
`0x9xxxxxxx` phandle form found in some older examples is not that encoding; when we used it,
`app_key_gen` later failed with `-15` (`TKM_ERR_KEY_NOT_EXIST`). Use the raw handle.

## Key continuity across VM restarts (verified)

A vid can be bound to a VM only once: after the VM exits — QMP `quit`, SIGTERM, and even a
clean in-guest `poweroff` all behave the same — the next bind fails with
`vpsp: [vpsp_try_bind_vtkm] kvm bind vtkm failed ... pspret: 61` and the guest logs
`tkm_device_info_get ... -61[TKM_ERR_NODE_LOCKED]`. Recovery is `vtkm_destroy -vid N` followed
by `vtkm_create -mode exclusive`; the destroy wipes the vid's key space.

Because of that, key material must be recoverable into a *newly created* vid. Verified sequence:

1. In the running VM, after creating the KEK and importing the SM2 app key:
   `hag tkm key_image_save -image keyimg.bin` → 736 bytes.
2. Guest `poweroff`, host `vtkm_destroy -vid 1`, `vtkm_create -mode exclusive`, reboot the VM
   with `-device psp,vid=1`.
3. In the new boot: `hag tkm key_image_load -image keyimg.bin` (reports success), then
   `hag tkm key_import -phandle 0x0200000A -password1 ... -key sm2.bin -password2 ...`.

Result: the exported public key is byte-identical to the pre-restart one
(sha256 `08e2dcca…9d0874` both sides) and a fresh signature verifies against the original
public key. So identity continuity across Pod/VM restarts is achievable.

What the image does and does not contain (measured through `hag tkm vtkm_key_usage_by_vid`):

- restored by `key_image_load`: internal keys — after the load the vid shows
  `KEK_SM4 used_num: 2`, and SM4 with the restored KEK handle works, including its password;
- **not** restored: application keys (`APP_KEY_SM2 used_num: 0`); they must be re-imported
  from the blob each boot. That is fine: the blob (3112 bytes) is encrypted under the parent
  KEK, so it is safe to store outside the TEE.

Both artifacts are opaque/encrypted: `key_image` has a small cleartext header and the key
payload is high-entropy (7.5 bits/byte over the whole file); the app-key blob is likewise
ciphertext.

## Open question

Whether `key_image` restores after a **host reboot** (device state reload) or on a different
Hygon machine was not tested — doing so would have required rebooting the shared host 178. The
vendor's `key_backup`/`key_restore` (`-scheme same_cpu | same_gen | dev_cert`, `-vid N`) is the
designed answer for durable backup and should be the fallback if `key_image` turns out to be
volatile across host reboots. `key_backup -scheme same_cpu -password ... -vid 1 -outfile ...`
returned a usage error in our guest and was not pursued.

## Kata integration blockers

1. **`CONFIG_DEVMEM`.** Every Kata guest kernel on 178 (`config-6.6.0+-153-confidential-csv`,
   and all other `config-*`) has `# CONFIG_DEVMEM is not set`. libhct's mem2 path opens
   `/dev/mem` and mmaps the `-mem2` window; without `DEVMEM` vTKM cannot work in a Kata Pod at
   all. Fix = rebuild the Kata CSV kernel with `CONFIG_DEVMEM=y` (devmem on a confidential
   guest is restricted to non-RAM areas by `ARCH_HAS_DEVMEM_IS_ALLOWED`, which is already
   enabled) and re-baseline the CSV MEASUREMENT.
2. **QEMU wrapper.** The Kata runtime class must add `-device psp,vid=N -mem2
   base=512G,size=32M` to the sandbox QEMU invocation (a wrapper like the vCCP one).
3. **kernel_params.** `memmap=32M$512G` must reach the guest cmdline; Kata's
   `kernel_params` is the natural place, but check how Kata quotes `$`.
4. **Per-Pod vid lifecycle.** Create an exclusive vid before sandbox start, bind it, and
   `vtkm_destroy` after exit. A crash that skips the destroy leaves the vid locked forever
   (only destroy+create recovers); the stop/cleanup hook must be idempotent and always run.
5. **TAA code.** Key operations must move to SDF handles (no private key in process memory),
   and `DeriveSealingKey` (`internal/store/sealed_state.go:107`), which derives the SM4 state
   key from the SM2 private scalar, has to be replaced — the existing CSV hardware sealing-key
   path is the candidate. The key image and the app-key blob have to be stored by TAA (sealed
   state) and restored at startup.

## Security model

vTKM satisfies the hard requirement in the useful sense: the private key is generated inside
the TKM, is used by handle, and is never exported — signatures come out, key bytes do not.
The app-key blob and key image are ciphertext bound to the device.

The host still controls the vid lifecycle and the VM launch, so a malicious host can bind the
vid to a VM of its own and *use* the key by handle (active misuse), and it holds copies of the
blob and image (replay/denial). What it cannot do is read the private key. This is the usual
TEE-identity caveat, and it is strictly better than the vCCP path, where the key bytes
themselves cross to the host.

## Artifacts left behind

- Test VM artifacts on the guest overlay disk (`/root/vtkm-persist`: `d.bin`, `sm2.bin`,
  `keyimg.bin`, `p1.bin`, `s1.bin`, `s2.bin`), in `/data/var/lib/libvirt/images/csv2-vtkm-overlay.qcow2`.
- Launch script on the host: `/tmp/relaunch-vtkm.sh` (hardcodes `vid=1` and the `$` memmap).
- Host state at the end: test VM powered off, all exclusive vids destroyed
  (`Used_exclusive_vid_nums: 0`), only the shared vid 0 remains.
