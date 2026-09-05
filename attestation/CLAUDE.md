# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

This repo implements Hygon CSV attestation and sealing-key tooling for two paths:

- **User-mode VM path**: uses `vmmcall` directly from the guest to fetch attestation data or sealing keys.
- **Kernel/Kata path**: uses the `csv-guest` kernel misc device and an ioctl bridge when `/proc/self/pagemap` access is not usable inside the guest/container.

The shared ABI lives in `csv_status.h`; most implementation logic lives in `csv_sdk/csv_status.c`.

## Build and run

The Makefiles now default to the local GmSSL tree used in this environment:

- `/home/osr/src/fghdotio-gmssl/unpacked/GmSSL-main/include/`
- `/home/osr/src/fghdotio-gmssl/unpacked/GmSSL-main/`

Override `INCDIR` and `LIBDIR` on the command line if you have GmSSL installed elsewhere.

Common commands from the repo root:

```bash
make                          # build all default targets
make dynamic_csv_sdk          # build libcsv.so
make static_csv_sdk           # build libcsv.a
make vmmcall-get-attestation  # build user-mode attestation tool
make ioctl-get-attestation    # build kata/kernel attestation tool; also copies to get-attestation
make verify-attestation       # build report verifier
make get_key                  # build user-mode sealing-key tool
make ioctl_get_key            # build ioctl sealing-key tool
make calc-vm-digest           # build VM digest calculator
make dcu_attestation_demo     # build DCU attestation demo
make release_csv_cipher       # create reduced csv_cipher/ SDK/demo package
make clean                    # remove built binaries and libraries
```

There is no automated test suite. Use `make` as the compile check; it builds with `gcc -Wall`. The practical smoke flow is:

```bash
./vmmcall-get-attestation      # generates report.cert in VM/user-mode path
./ioctl-get-attestation        # generates report.cert and nonce.bin via /dev/csv-guest
./verify-attestation false     # verifies report.cert without certificate-chain validation
./verify-attestation true      # verifies report.cert and the certificate chain
./verify-attestation true oca.cert  # optional OCA certificate input
```

Other useful binaries:

```bash
./get_key
./ioctl_get_key
./calc-vm-digest <bios> <kernel> <initrd> <cmdline>
./dcu_attestation_demo
```

`verify-attestation` expects `report.cert` in the working directory. When chain verification is enabled, it downloads certificates from Hygon URLs and falls back to local files next to the executable when available (`hrk.cert`, `hsk_cek.cert`, optional OCA cert).

To bind custom data into a report, set `ATTESTATION_USERDATA` to exactly 128 hex characters (64 bytes). If unset, the SDK uses the literal default `user data`. The ioctl attestation wrapper reuses `nonce.bin` when present; otherwise it generates a nonce, writes `nonce.bin`, and `verify-attestation` compares that saved nonce if the file exists.

For Kata/container runs, the guest device must be available inside the container, for example:

```bash
sudo docker run --name csv -t -i -v /dev/csv-guest:/dev/csv-guest ubuntu bash
```

Then copy `ioctl-get-attestation` or `ioctl_get_key` into the container and run it there.

## Architecture overview

### Shared data model and ABI

`csv_status.h` is the central contract between all parts of the project. It defines:

- attestation report layouts
- certificate-chain layouts
- ioctl payloads
- constants for report, nonce, and cert sizes
- shared helper prototypes used across the SDK and demos

Treat changes here as ABI changes; they affect the kernel bridge, the SDK, and every CLI tool.

### SDK implementation (`csv_sdk/csv_status.c`)

This is the core of the repository. It handles:

- user-mode attestation via `vmmcall`
- session nonce generation and MAC verification
- certificate-chain validation with GmSSL/OpenSSL SM2/SM3 APIs
- loading certs from disk or downloading them with `curl`
- exporting public keys to PEM
- helper functions for VM status and random generation

The file is shared by both the report and sealing-key paths, so changes here tend to affect most binaries.

### Thin CLI wrappers

The top-level tools are intentionally small:

- `vmmcall_get_attestation.c` / `vmmcall_get_key.c`: user-mode VM entry points
- `ioctl_get_attestation.c` / `ioctl_get_key.c`: Kata/kernel entry points
- `verify_attestation.c`: report verification and optional OCA export
- `calc_vm_digest.c`: builds the CSV hash table from BIOS/kernel/initrd/cmdline inputs and computes the SM3 digest used for boot measurement
- `dcu_attestation_demo.c`: hardware-specific DCU attestation demo that iterates over `/sys/devices/virtual/kfd/kfd/topology/nodes` and talks to `/dev/mkfd`

### Kernel bridge (`csv-guest.c`)

`csv-guest.c` is a miscdevice kernel module that exposes `/dev/csv-guest`. Its ioctl path:

1. copies user data into kernel memory
2. issues the attestation hypercall
3. copies the result back to user space

This is the path intended for Kata/container setups where the user-mode pagemap approach is blocked.

### Release variant

`make release_csv_cipher` creates a reduced `csv_cipher/` package around `csv_status.c` and `demo.c`, using `release_csv_cipher.Makefile` as that package's Makefile. That release Makefile defaults to `/opt/gmssl/include/` and `/opt/gmssl/lib/`, unlike the top-level Makefile, so override `INCDIR`/`LIBDIR` or edit the release package if you build it in this local environment.

## Files that matter operationally

These are the runtime inputs/outputs most commands expect:

- `report.cert` — generated attestation report
- `nonce.bin` — nonce saved by the ioctl attestation path
- `hrk.cert` — HRK root cert used for chain validation
- `hsk_cek.cert` — HSK/CEK bundle used for chain validation

## Practical gotchas

- The build defaults to the local GmSSL tree under `/home/osr/src/fghdotio-gmssl/unpacked/GmSSL-main`; override `INCDIR` and `LIBDIR` if you relocate it.
- `verify-attestation true` may try to fetch certs from the network if local ones are missing.
- The user-mode attestation path depends on `/proc/self/pagemap`; that is why the ioctl/kernel path exists for Kata-style isolation.
- `dcu_attestation_demo` is hardware- and driver-specific; it will not run unless the DCU device stack is present.
