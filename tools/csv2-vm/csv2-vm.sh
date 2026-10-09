#!/usr/bin/env bash
#
# csv2-vm.sh - create and manage the Hygon CSV2 confidential VM on the Hygon host.
#
# The VM is a QEMU/KVM confidential guest with encrypted memory (CSV2 = the
# register-encrypting generation, equivalent to AMD SEV-ES). It is NOT managed by
# libvirt, so `virsh list` will not show it. State lives in a qcow2 overlay;
# the base image is used read-only as a backing file and is never modified.
#
# Recorded from a verified bring-up on 2026-09-28 against host root@172.16.10.178.
# See also the host-side originals: /home/wj/csv2-8c16g.sh (and its -status.sh).
#
# Files and capabilities a CSV2 guest needs (see `deps` to check them):
#
#   host side - must exist before `up`
#     $CSV2_BASE_DISK          guest base image, used read-only as the backing file.
#                              Supplies the guest kernel, the CSV2-patched kernel
#                              modules (csv-guest.ko) and a preinstalled OS, so a
#                              new instance is a COW overlay rather than an install.
#     $HOST_OVMF               OVMF built with confidential-guest support, and with a
#                              populated kernel-hashes region. A build that only
#                              advertises the region's GUID is refused by QEMU;
#                              `up` checks this before launching.
#     /dev/sev                 PSP device. Memory encryption is impossible without it.
#     /etc/qemu/bridge.conf    must allow the bridge, or QEMU refuses to attach it.
#     <bridge>                 LAN uplink; also where the guest's DHCP lease comes from.
#
#   host side - extracted from the base image by `up`, for measured boot
#     $HOST_KERNEL             the guest's own kernel and its matching initramfs,
#     $HOST_INITRD             copied out of /boot inside the base image. QEMU
#                              hashes them into the launch measurement, so they
#                              must exist as real host files. Re-extract them
#                              after the base image is replaced.
#
#   guest side - already inside the base image, nothing to stage
#     /lib/modules/$(uname -r)/kernel/drivers/virt/coco/csv-guest/csv-guest.ko.xz
#                              provides /dev/csv-guest, the attestation interface.
#                              Not loaded by default; `up` and `verify` modprobe it.
#
#   DCU mode (CSV2_DCU=1) - additionally required, see "DCU passthrough" below
#     $KATA_KERNEL             the Hygon kata kernel. DCU mode boots this instead
#                              of the base image's kernel, because only it has the
#                              hycu driver stack. Swapping the kernel is what
#                              changes the launch measurement, so the mode is a
#                              switch and never the default.
#     $KATA_ROOTFS             kata root filesystem, source of the hycu modules
#                              and of the version-pinned firmware they load.
#     $KATA_QEMU               the Hygon QEMU build. The stock one hangs forever
#                              inside the hycu driver's PCIe initialisation and
#                              then segfaults when the DCU sits behind a root
#                              port, so it cannot be used for this mode.
#     $DCU_BASE_DISK           built once by `up` from the base image plus the
#                              kata modules/firmware; shared by every DCU
#                              instance. `dcu-base` rebuilds it.
#     guestfish, qemu-img      used to build the disk images above.
#
#   verification only - optional, needed by `verify` and `measure`
#     $SMOKE_BIN               TAA attestation smoke test, copied into the guest.
#     $CERT_DIR/hrk.cert, $CERT_DIR/hsk_cek.cert
#                              Hygon root and endorsement certs, for chain checking.
#     $MEASURE_TOOL            recomputes the launch measurement from host files.
#     $GET_ATTESTATION_BIN     fetches the report the running guest actually gets.
#
# Usage:
#   ./tools/csv2-vm/csv2-vm.sh deps     list the required files and whether they exist
#   ./tools/csv2-vm/csv2-vm.sh up       create (if needed) and boot the VM
#   ./tools/csv2-vm/csv2-vm.sh status   read-only status + CSV2 encryption check
#   ./tools/csv2-vm/csv2-vm.sh measure  the launch measurement this configuration
#                                       should produce, next to the one the guest
#                                       actually reports
#   ./tools/csv2-vm/csv2-vm.sh verify   run the TAA CSV attestation smoke test in the guest
#   ./tools/csv2-vm/csv2-vm.sh ssh      open a shell in the guest
#   ./tools/csv2-vm/csv2-vm.sh down     stop the VM and clean runtime files
#   ./tools/csv2-vm/csv2-vm.sh down --purge-disk
#                                       also delete the overlay disk (DESTRUCTIVE:
#                                       discards all guest state; the read-only base
#                                       image is left alone so it can be recreated)
#   ./tools/csv2-vm/csv2-vm.sh dcu-base rebuild the shared DCU base image from the
#                                       current kata assets (DCU mode only)
#   ./tools/csv2-vm/csv2-vm.sh pod-up   create the DCU test pod on the cluster
#   ./tools/csv2-vm/csv2-vm.sh pod-status
#                                       read-only status of that pod
#   ./tools/csv2-vm/csv2-vm.sh pod-down delete it, and the NodePort Service with it
#
# Measured boot. The VM is launched with -kernel/-initrd/-append and
# kernel-hashes=on, so the PSP measures more than the firmware: QEMU builds a
# hash table into a reserved area of the firmware covering exactly three values -
# the kernel, the initramfs and the command line. The launch measurement becomes
#
#   MEASUREMENT = SM3( OVMF || table{ cmdline, initrd, kernel } )
#
# Without -kernel there is nothing to hash and the measurement degrades to
# SM3(OVMF) alone. That pins the firmware and nothing else: the kernel, the
# initramfs and the whole root filesystem stay unmeasured, so anything loaded
# from the disk can be replaced without moving the measurement. `measure` prints
# the expected value for the current configuration and, when the VM is up, the
# value the guest actually reports.
#
# DCU mode still passes an -initrd, so the formula above is unchanged there. It is
# a deliberately empty cpio archive, not an oversight: csv-measure.py only builds
# the hash table when kernel, initrd and cmdline are all supplied, so dropping the
# initrd would silently change the shape of the measurement. See ensure_dcu_boot_images.
#
# Credentials come from the environment, never from this file:
#   CSV2_HOST       ssh target of the KVM host      (default root@172.16.10.178)
#   CSV2_HOST_PASS  password for the host           (omit to use ssh keys)
#   CSV2_GUEST_PASS password inside the guest       (default root)
#
# Any number of independent instances can be created by overriding the identity
# of the VM. Each instance needs its own name, MAC, QMP port and VNC display:
#   CSV2_VM_NAME    instance name                   (default csv2-8c16g)
#   CSV2_VM_MAC     guest NIC MAC                   (default 52:54:00:12:34:56)
#   CSV2_VM_IP      guest IP; leave unset to auto-discover after boot
#   CSV2_QMP_PORT   host QMP port                   (default 2223)
#   CSV2_VNC_DISPLAY host VNC display, empty to disable (default 9; not every
#                    QEMU build has VNC, and `up` says so if this one does not)
#   CSV2_VM_VCPUS / CSV2_VM_MEM_MB                  (default 8 / 16384)
#   CSV2_DISK       overlay path                    (default <images>/<name>-overlay.qcow2)
#
# A guest can also be given host PCI devices by VFIO passthrough. This is off
# unless asked for, and the device is not part of the launch measurement:
#   CSV2_VFIO_DEVICES  host addresses, space or comma separated (e.g. "c3:00.0")
#
# DCU passthrough. A pass-through device is only useful if the guest has a driver
# for it, and the base image's kernel does not have one for the DCU. DCU mode
# swaps in the Hygon kata kernel, which does:
#   CSV2_DCU=1         boot with the kata kernel and the hycu driver stack, and
#                      pass the DCU through by default (default: off)
#   CSV2_DCU_DEVICES   override which host devices are passed through in this mode
#                      (default: the DCU, c3:00.0)
#   CSV2_KATA_SHARE    where the kata assets live       (default /opt/kata/share)
#   CSV2_DCU_BASE_DISK shared DCU base image            (default <images>/csv2-dcu-base.qcow2)
#   CSV2_QEMU          QEMU binary for this mode        (default /opt/kata/bin/qemu-system-x86_64)
#   CSV2_POLICY, CSV2_CBITPOS, CSV2_REDUCED_PHYS_BITS
#                      CSV2 launch parameters (default 0x5 / 47 / 5). None of the
#                      three is hashed into the measurement, so changing them only
#                      needs `down` and `up` - a matching `measure` stays matching.
#                      The kata runtime uses 7 / 47 / 1; reduced-phys-bits is the
#                      first thing to try if the guest's DCU DMA misbehaves.
#
# The DCU's binding to vfio-pci is made once, at boot, by the unit that ships with
# the vendor kit (/home/wj/dcu/README.md, dcu-bind-vfio.service). Do not move it by
# hand. `rmmod` and `unbind` are not safe here: the vendor module's probe
# (hycu_pci_fixup_header) deadlocks on re-enumeration, and once it has, even unbind
# blocks on the device lock. `remove` + `rescan` is what re-runs that probe in the
# first place, and it wedges the card until the host is rebooted. When the card is
# not on vfio-pci, `up` refuses to start and names the recovered paths instead.
#
# DCU mode also changes the disk bus and the root= argument (see the note above
# VM_APPEND), so an overlay built for one mode cannot be booted in the other. The
# overlay name is mode-specific and `up` checks the backing chain rather than
# trusting the name. Its QEMU is built without VNC, so a DCU guest has no VNC
# console - log in over ssh, or read the serial log at $HOST_CONSOLE_LOG.
#
# A DCU guest boots to `degraded`, with four units failed. All four come from
# running the kata kernel over the base image and none of them matter here:
# boot.mount (the vfat ESP that kernel cannot mount; nofail keeps it non-fatal),
# kdump.service (crashkernel is on the cmdline but this kernel ships no initramfs
# for it), NetworkManager-wait-online and systemd-sysctl (the base image's sysctl
# settings the kata kernel does not carry). ssh, /dev/csv-guest and the DCU driver
# are all unaffected - do not go chasing the exit status.
#
# Every later command must be given the same overrides, or it will address the
# default instance instead. The guest is addressed by the LAN DHCP server, so an
# instance without CSV2_VM_IP is discovered after boot: first from the bridge
# neighbour table, then by reading `hostname -I` over the serial console.
#
# The DCU test pod. There are two ways to get a TEE with the DCU in it, and they are
# different routes, not two settings of one:
#
#   up (+ CSV2_DCU=1)  this script builds the VM itself, with QEMU, and passes the
#                      DCU in by VFIO. The guest is one this script controls.
#   pod-up             Kubernetes does it: the pod names the vendor's kata CoCo
#                      runtime, which builds an encrypted VM and hands the DCU to
#                      it. `pod-*` never touches QEMU, libvirt or the disk images
#                      above; it needs a cluster on the host instead.
#
# Both routes want the card on vfio-pci, so the paragraph above applies to each.
# The pod route is the one that has actually been measured working end to end, and
# `dcu-tee-test` is a shared test pod - other sessions may be using it, and there is
# one DCU on the host, so `pod-up` while it exists fails rather than replacing it.
#
# What the pod is, is written in the template that ships next to this script:
#   tools/csv2-vm/dcu-tee-pod.yaml
# Pod name, image, runtimeClass and NodePort are read back out of that file rather
# than listed here, so the checks and the applied object cannot disagree. It is the
# vendor's template, vendored so the pod can be reproduced from this repository; the
# only things this script supplies are the two the file has placeholders for - the
# initdata blob and the pod's ssh password.
#
#   CSV2_POD_TEMPLATE   the file above, if you keep your own copy
#   CSV2_POD_NAMESPACE  namespace for the pod and its Service (default default)
#   CSV2_POD_PASSWORD   password for root inside the pod. No default on purpose:
#                       this repository is committed to automatically, so a literal
#                       would land in its history, and the pod's NodePort is
#                       reachable from the whole LAN. Unset, `pod-up` generates one
#                       and prints it in the summary.
#   CSV2_POD_REGISTRY   registry the guest pulls from (default <host>:31313). It is
#                       a NodePort Service on the cluster, not a daemon on the host,
#                       so nothing listens on that port in `ss` output.
#   CSV2_POD_IMAGE_UPSTREAM
#                       tag `pod-up` pushes to that registry when it lacks
#                       vllm:ubuntu-dtk (default the harbor.sourcefind.cn one).
#                       `--skip-push` makes a missing image an error instead.
#   CSV2_POD_INITDATA   the CoCo initdata file on the host, which is what carries the
#                       registry's CA into the guest.
#   CSV2_POD_PULL_TIMEOUT
#                       seconds to wait for Ready (default 2400). The image is
#                       25.6GB and the guest pulls it itself.
#
# `pod-up` tags and pushes the 25.6GB image when the registry does not have it, which
# takes minutes and is the only step with a side effect beyond the cluster. `pod-up
# --dry-run` stops after rendering, and prints the file it rendered.
#
# Examples:
#   CSV2_HOST_PASS='...' ./tools/csv2-vm/csv2-vm.sh up
#   CSV2_HOST_PASS='...' ./tools/csv2-vm/csv2-vm.sh verify
#
#   # A second, independent instance alongside the first.
#   export CSV2_VM_NAME=csv2-fresh CSV2_VM_MAC=52:54:00:12:34:57
#   export CSV2_QMP_PORT=2224 CSV2_VNC_DISPLAY=10
#   CSV2_HOST_PASS='...' ./tools/csv2-vm/csv2-vm.sh up
#   CSV2_HOST_PASS='...' ./tools/csv2-vm/csv2-vm.sh verify
#   CSV2_HOST_PASS='...' ./tools/csv2-vm/csv2-vm.sh down
#
set -euo pipefail

# ------------------------------- configuration -------------------------------

CSV2_HOST="${CSV2_HOST:-root@172.16.10.178}"
CSV2_HOST_PASS="${CSV2_HOST_PASS:-}"
CSV2_GUEST_PASS="${CSV2_GUEST_PASS:-root}"

# DCU passthrough mode. Off by default: it swaps the guest kernel for the Hygon
# kata one, which changes the launch measurement permanently, and it needs a
# different QEMU. Read the mode through use_dcu() so there is one definition of
# what "on" means.
CSV2_DCU="${CSV2_DCU:-0}"
use_dcu() { [ "$CSV2_DCU" != 0 ]; }
# Same test as 0/1, for the host-side scripts below: those run on the KVM host and
# cannot call use_dcu, so the mode is expanded here instead and they test this.
CSV2_DCU_ON=0
if use_dcu; then CSV2_DCU_ON=1; fi

# Guest identity. The MAC is fixed so the LAN bridge hands out the same lease,
# which keeps the guest reachable at a stable address across reboots.
VM_NAME="${CSV2_VM_NAME:-csv2-8c16g}"
VM_MAC="${CSV2_VM_MAC:-52:54:00:12:34:56}"
# Empty means "discover after boot" - a freshly created instance has no known
# address until the LAN DHCP server has answered.
VM_IP="${CSV2_VM_IP:-}"
VM_VCPUS="${CSV2_VM_VCPUS:-8}"
VM_MEM_MB="${CSV2_VM_MEM_MB:-16384}"

HOST_DISK_DIR=/data/var/lib/libvirt/images
# The overlay is bound to the mode it was built for: DCU mode changes the disk bus
# and the root= argument, so a shared name would boot the wrong thing without
# saying so. `up` also checks the backing chain rather than trusting the name.
if use_dcu; then
    HOST_DISK="${CSV2_DISK:-$HOST_DISK_DIR/$VM_NAME-dcu-overlay.qcow2}"
else
    HOST_DISK="${CSV2_DISK:-$HOST_DISK_DIR/$VM_NAME-overlay.qcow2}"
fi
# Read-only devkit base image shipped by Hygon; only ever used as a backing file.
HOST_BASE_DISK="${CSV2_BASE_DISK:-/opt/hygon/csv/vm.qcow2}"
# Firmware to boot. Must be built with confidential-guest support AND, because
# this script always asks for kernel-hashes, must carry a populated hashes-table
# region: OVMF advertises one under SEV_HASH_TABLE_RV_GUID, but the plain build
# ships it empty (base=0x0 size=0x0) and QEMU refuses to launch. OVMFCSV.fd is
# the firmware the Kata sandbox VMs use and is populated (base=0x80c000
# size=0xc00). `up` verifies this rather than trusting the path.
HOST_OVMF="${CSV2_OVMF:-/opt/kata/share/ovmf/OVMFCSV.fd}"
HOST_BRIDGE=br0

# Measured boot. The guest kernel and initramfs are copied out of the base image
# because QEMU hashes them from the host side, not from inside the guest.
HOST_BOOT_DIR="${CSV2_BOOT_DIR:-$HOST_DISK_DIR/csv2-boot}"
# KERNEL_VERSION must name a kernel that is actually present in the base image;
# `up` lists what is available if it does not. Only the non-DCU path boots it.
KERNEL_VERSION="${CSV2_KERNEL_VERSION:-6.6.0-111.0.0.103.oe2403.x86_64}"

# ---------------------------------- DCU mode ----------------------------------
# Everything that differs between the two modes is resolved here, so the rest of
# the script reads plain variables and never asks which mode it is in. The
# non-DCU values above are the ones this script has always used; DCU mode changes
# four things, all of which are needed to get a driver bound to the DCU:
#
#   kernel     the kata kernel is the only one with the hycu stack. Its modules
#              are version-locked (KATA_KERNEL_VERSION) and it has no ATA/IDE
#              support at all, so the disk has to move to virtio, and no VFAT, so
#              the base image's /boot entry has to become non-fatal.
#   disk bus   -hda is IDE, which that kernel cannot see.
#   root=      root=UUID= is resolved by the initramfs, and this mode passes a
#              deliberately empty one; the kernel needs the device path instead.
#   QEMU       the stock QEMU hangs forever inside the hycu driver's PCIe init,
#              and segfaults when the DCU sits behind a root port. The kata build
#              gets past both, but looks for its bridge helper under its own
#              prefix, so -netdev bridge has to be pointed at the system one.
KATA_SHARE="${CSV2_KATA_SHARE:-/opt/kata/share}"
KATA_QEMU=/opt/kata/bin/qemu-system-x86_64
KATA_KERNEL="$KATA_SHARE/kata-containers/vmlinuz-hycu-confidential-csv.container"
KATA_ROOTFS="$KATA_SHARE/kata-containers/kata-containers-hycu-confidential-csv.img"
# Names the module and firmware directories inside the kata root filesystem, and
# the firmware search path the kernel uses. It must match KATA_KERNEL.
KATA_KERNEL_VERSION=6.6.0-hycu-confidential-csv+
# Built once from the base image and shared by every DCU instance, so it is a
# cache and not instance state: `down --purge-disk` keeps it, `dcu-base` rebuilds
# it. `up` rebuilds it automatically when the kata assets it was built from have
# changed.
DCU_BASE_DISK="${CSV2_DCU_BASE_DISK:-$HOST_DISK_DIR/csv2-dcu-base.qcow2}"
DCU_BASE_STAMP="$DCU_BASE_DISK.stamp"
# Bump this whenever the way the base is assembled changes. The stamp can only
# compare the kata assets, so without this a base built by an older, wrong recipe
# keeps looking valid and is silently reused - which is exactly how a mistake in
# the build steps survives every later rebuild.
DCU_BASE_RECIPE=2
DCU_INITRD="$HOST_BOOT_DIR/initramfs-hycu-minimal.cpio"
# The Hygon DCU. Matched by vendor:device everywhere rather than by slot: the
# slot is 00:04.0 under the stock machine type but 01:00.0 behind a q35 root
# port, and :00:00.0 means "any" to match by id alone.
DCU_VENDOR=1d94
DCU_DEVICE=6211
DCU_HOST_ADDR=c3:00.0

# Resolved for the current mode.
HOST_BACKING="$HOST_BASE_DISK"
HOST_QEMU=/usr/bin/qemu-system-x86_64
HOST_KERNEL="${CSV2_KERNEL:-$HOST_BOOT_DIR/vmlinuz-$KERNEL_VERSION}"
HOST_INITRD="${CSV2_INITRD:-$HOST_BOOT_DIR/initramfs-$KERNEL_VERSION.img}"
# Byte-identical to the base image's own grub entry, so a direct kernel boot
# behaves like the firmware's boot path. root= is a filesystem UUID, and an
# overlay inherits the UUID of the image it was created from.
VM_APPEND="${CSV2_APPEND:-root=UUID=1f4c3ba2-226d-4365-8d1f-30d80117c355 console=tty1 console=ttyS0 rootfstype=ext4 rd.shell rd.debug quiet oops=panic softlockup_panic=1 nmi_watchdog=1 rd.shell=0 selinux=0 crashkernel=256M panic=3}"
VFIO_DEVICES="$(printf '%s' "${CSV2_VFIO_DEVICES:-}" | tr ',' ' ')"
# Seconds to wait for a login prompt before trying to read the address off the
# console. A DCU guest takes about 70-90s to get there against roughly 20s plain.
GUEST_BOOT_WAIT=60

if use_dcu; then
    HOST_BACKING="$DCU_BASE_DISK"
    HOST_QEMU="${CSV2_QEMU:-$KATA_QEMU}"
    HOST_KERNEL="${CSV2_KERNEL:-$KATA_KERNEL}"
    HOST_INITRD="${CSV2_INITRD:-$DCU_INITRD}"
    # Same command line as the plain mode in every token but root=. /dev/vda2 is
    # the base image's ext4 root partition; vda1 is the vfat ESP, which this
    # kernel cannot mount, so the base image's fstab entry for /boot is made
    # non-fatal when the DCU base is built.
    VM_APPEND="${CSV2_APPEND:-root=/dev/vda2 console=tty1 console=ttyS0 rootfstype=ext4 rd.shell rd.debug quiet oops=panic softlockup_panic=1 nmi_watchdog=1 rd.shell=0 selinux=0 crashkernel=256M panic=3}"
    # Passing the DCU through is the point of the mode, so it is the default here
    # rather than something to remember to ask for.
    VFIO_DEVICES="$(printf '%s' "${CSV2_VFIO_DEVICES:-${CSV2_DCU_DEVICES:-$DCU_HOST_ADDR}}" | tr ',' ' ')"
    GUEST_BOOT_WAIT=180
fi

# Tools that only `measure` needs: the digest calculator shipped with the Hygon
# CoCo package, and a guest-side report reader.
MEASURE_TOOL="${CSV2_MEASURE_TOOL:-/opt/hygon/csv/confidential-containers/scripts/csv-measure.py}"
GET_ATTESTATION_BIN="${CSV2_GET_ATTESTATION:-/opt/hygon/csv/attestation/get-attestation}"

HOST_PIDFILE="/run/$VM_NAME.pid"
HOST_SERIAL="/run/$VM_NAME.serial"
HOST_CONSOLE_LOG="/var/log/$VM_NAME-console.log"
HOST_QMP_PORT="${CSV2_QMP_PORT:-2223}"
HOST_VNC_DISPLAY="${CSV2_VNC_DISPLAY:-9}"

# policy=0x5 decodes as NODBG(0x1) | ES(0x4). The ES bit is what makes this CSV2
# rather than CSV1: guest register state is encrypted, not just memory.
# cbitpos/reduced-phys-bits are Hygon-specific (AMD parts use 51/1).
#
# None of the three is hashed into the measurement, so they can be changed with
# just `down` and `up` - there is no measurement mismatch to chase afterwards.
# They stay at the values this script has always used; the kata runtime uses
# 7/47/1, and reduced-phys-bits is the first one to try if DMA from a
# passed-through device misbehaves, since it sets the guest's C-bit geometry
# while the DCU maps a 64G BAR.
VM_POLICY="${CSV2_POLICY:-0x5}"
VM_CBITPOS="${CSV2_CBITPOS:-47}"
VM_REDUCED_PHYS_BITS="${CSV2_REDUCED_PHYS_BITS:-5}"

# Host PCI devices to hand to the guest by VFIO passthrough, as host addresses
# separated by spaces or commas (e.g. "c3:00.0"). Empty means none, which is the
# default for a plain CSV2 guest; DCU mode defaults to the DCU. Set either
# CSV2_VFIO_DEVICES (both modes) or CSV2_DCU_DEVICES (DCU mode only).
#
# Each device must already be bound to vfio-pci, and every device sharing its
# IOMMU group must be listed too - the group is the unit the IOMMU can isolate,
# so passing one member through without the others would let the guest reach
# memory belonging to the rest. `up` verifies both.
#
# Note that a passed-through device is NOT covered by the launch measurement:
# MEASUREMENT hashes the firmware, command line, initramfs and kernel only, so a
# device can be added or swapped without the report changing. Anything relying
# on the device has to establish its trust separately.
#
# Passing a device through only helps if the guest can drive it. A device with no
# driver still enumerates - the DCU comes up with its BARs assigned and its 64G
# window mapped - but nothing binds it and no /dev node appears. The base image's
# kernel has no hycu stack and refuses its vermagic, which is why DCU mode exists.
#
# What DCU mode does about it:
#
#   - Boots the kata kernel and gives it the kata modules and firmware. The
#     modules are version-locked to that kernel, so they come with it or not at
#     all; the firmware is looked up under /lib/firmware/<kernel release>/, so it
#     has to be injected under the matching name.
#   - Uses the kata QEMU with q35 and a root port per device. The stock QEMU
#     hangs forever inside the hycu driver's PCIe initialisation under the
#     default machine type, and segfaults when the DCU is put behind a root port
#     on q35, so neither the stock binary nor the default machine type will do.
#   - Keeps the DCU's own driver stack out of the measurement, like any other
#     passed-through device. The measurement does move, but only because the
#     kernel and command line changed.
#
# Two things the DCU brings along whatever the mode:
#
#   - Its 128K expansion ROM is invalid (starts with 0xaa55, no PCIR), so QEMU
#     may warn "Cannot read device rom" / "Device option ROM contents are
#     probably invalid" and the guest cannot claim the ROM BAR. It is a warning,
#     not a failure, and it is intermittent - QEMU only reads the ROM when it
#     decides to. Add rombar=0 to the -device to silence it, at the cost of never
#     getting a ROM for any guest that could use one.
#   - It has no reset mechanism (the vendor's hycu_pci_fixup_header deliberately
#     marks it NO_BUS_RESET, because a bus reset breaks CSV2 passthrough), so
#     QEMU prints "Cannot reset device ..., no available reset mechanism" twice
#     per launch. Harmless, and deterministic.
#
# A DCU guest also takes about 70-90s to reach a login prompt instead of ~20s.
# `up` waits for the prompt before reading the address off the console, so it
# covers this; see GUEST_BOOT_WAIT.


# Attestation smoke test, run inside the guest (host paths).
SMOKE_BIN="${CSV2_SMOKE_BIN:-/root/taa/csv-go-smoke}"
CERT_DIR="${CSV2_CERT_DIR:-/root/taa}"

# The DCU test pod - see the header. None of this is used by the QEMU commands.
POD_FILE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POD_TEMPLATE="${CSV2_POD_TEMPLATE:-$POD_FILE_DIR/dcu-tee-pod.yaml}"
POD_NAMESPACE="${CSV2_POD_NAMESPACE:-default}"

# No default: see the header. The pod's sshd gets this and nothing else does.
POD_PASSWORD="${CSV2_POD_PASSWORD:-}"

# The registry is derived from the host rather than written twice, but the template
# names it too, and `pod-up` refuses if the two disagree - pushing one tag while the
# guest pulls another is a failure that looks like a pull timeout.
POD_REGISTRY="${CSV2_POD_REGISTRY:-${CSV2_HOST#*@}:31313}"
POD_IMAGE_UPSTREAM="${CSV2_POD_IMAGE_UPSTREAM:-harbor.sourcefind.cn:5443/dcu/admin/base/vllm:0.9.2-ubuntu22.04-dtk26.04-0130-py3.10-20260202}"
POD_INITDATA="${CSV2_POD_INITDATA:-/root/test/deployment/tools/build-and-install/test-hygon-coco/initdata.v1.toml}"
POD_PULL_TIMEOUT="${CSV2_POD_PULL_TIMEOUT:-2400}"

# ------------------------------- ssh plumbing --------------------------------

if [ -n "$CSV2_HOST_PASS" ]; then
    command -v sshpass >/dev/null || { echo "sshpass not found but CSV2_HOST_PASS is set" >&2; exit 1; }
    export SSHPASS="$CSV2_HOST_PASS"
    SSH=(sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "$CSV2_HOST")
    SCP=(sshpass -e scp -o StrictHostKeyChecking=accept-new)
else
    SSH=(ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "$CSV2_HOST")
    SCP=(scp -o StrictHostKeyChecking=accept-new)
fi

# Run a script on the KVM host; stdin is forwarded.
#
# The body is an *unquoted* heredoc, so the local shell expands it on the way out:
# every $ and backtick the remote side should see has to be escaped. A bare pair of
# backticks in a comment is a command substitution here, not punctuation - and one
# wrapping `bash -s` does not merely fail, it reads the very stdin the body was
# going to travel on. That is why the comments below escape theirs.
host_script() { "${SSH[@]}" bash -s; }
# Run a command on the KVM host.
host() { "${SSH[@]}" "$@"; }

# Run a script inside the guest, hopping through the host.
guest_script() {
    local inner
    inner=$(cat)
    host env SSHPASS="$CSV2_GUEST_PASS" bash -s <<EOF
sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 root@$VM_IP bash -s <<'GUEST_EOF'
$inner
GUEST_EOF
EOF
}

vm_pid() { host "cat '$HOST_PIDFILE' 2>/dev/null || true"; }

# /dev/csv-guest is provided by the csv-guest module and is NOT loaded by default.
# Without it TAA's attestation path finds no device and silently degrades to
# simulation mode, so load it before anything that needs the device.
ensure_csv_guest_device() {
    guest_script <<'GUEST'
if [ -c /dev/csv-guest ]; then
    echo "  /dev/csv-guest present"
else
    modprobe csv-guest
    echo "  modprobe csv-guest done"
fi
ls -la /dev/csv-guest
GUEST
}

# Kernel hashes need somewhere in the firmware to be written. The region is
# advertised by a GUID entry; a build that carries the GUID but no geometry is
# unusable, and QEMU only says so after the guest would have started. Both modes
# need this, so it is checked before either one prepares its boot images.
check_ovmf_hashes_region() {
    host_script <<EOF
set -e
[ -f "$HOST_OVMF" ] || { echo "  firmware $HOST_OVMF is missing" >&2; exit 1; }
python3 - "$HOST_OVMF" <<'PY'
import struct, sys
raw = open(sys.argv[1], 'rb').read()
guid = (bytes.fromhex('1f375572') + bytes.fromhex('3b3a') + bytes.fromhex('044b')
        + bytes.fromhex('927b') + bytes.fromhex('1da6efa8d454'))
off = raw.find(guid)
if off < 0:
    raise SystemExit('  firmware has no hashes-table GUID; it cannot measure a kernel')
base, size = struct.unpack_from('<II', raw, off + 16)
if not base or not size:
    raise SystemExit(
        '  firmware hashes-table region is empty (base=0x%x size=0x%x)\n'
        '  set CSV2_OVMF to a CSV build that populates it, e.g.\n'
        '  /opt/kata/share/ovmf/OVMFCSV.fd' % (base, size))
print('  firmware reserves 0x%x bytes at 0x%x for kernel hashes' % (size, base))
PY
EOF
}

# Both modes hash a kernel and an initramfs; they differ in where the pair comes
# from. Kept under one name so the launch path and `measure` cannot disagree
# about which files are measured.
ensure_boot_images() {
    check_ovmf_hashes_region
    if use_dcu; then
        ensure_dcu_boot_images
    else
        ensure_oe_boot_images
    fi
}

# The base image's own kernel, copied out so QEMU can hash it from the host side.
ensure_oe_boot_images() {
    host_script <<EOF
set -e
if [ -f "$HOST_KERNEL" ] && [ -f "$HOST_INITRD" ]; then
    echo "  reusing extracted kernel and initramfs in $HOST_BOOT_DIR"
    exit 0
fi

if ! guestfish --ro -a "$HOST_BASE_DISK" -i exists "/boot/vmlinuz-$KERNEL_VERSION" >/dev/null 2>&1; then
    echo "  kernel $KERNEL_VERSION is not in $HOST_BASE_DISK" >&2
    echo "  kernels available there:" >&2
    guestfish --ro -a "$HOST_BASE_DISK" -i ls /boot 2>/dev/null \\
        | grep '^vmlinuz-' | sed 's/^vmlinuz-/    /' >&2
    echo "  set CSV2_KERNEL_VERSION to one of them" >&2
    exit 1
fi

mkdir -p "$HOST_BOOT_DIR"
guestfish --ro -a "$HOST_BASE_DISK" -i copy-out "/boot/vmlinuz-$KERNEL_VERSION" "$HOST_BOOT_DIR/" >/dev/null
guestfish --ro -a "$HOST_BASE_DISK" -i copy-out "/boot/initramfs-$KERNEL_VERSION.img" "$HOST_BOOT_DIR/" >/dev/null
echo "  extracted $KERNEL_VERSION from $HOST_BASE_DISK"
EOF
}

# DCU mode's pair. The kernel is the kata one, used where it lies - it is already
# a host file, so copying it would only add a second copy to keep in sync. The
# initramfs is generated.
ensure_dcu_boot_images() {
    host_script <<EOF
set -e
[ -f "$KATA_KERNEL" ] || { echo "  kata kernel missing: $KATA_KERNEL" >&2; exit 1; }
echo "  kernel   $HOST_KERNEL"

mkdir -p "$HOST_BOOT_DIR"

# The kata kernel is what we want to run, but csv-measure.py only builds the
# kernel-hashes table when kernel, initrd and cmdline are ALL supplied, so this
# mode has to pass an -initrd or the measurement silently changes shape. This is
# the smallest valid one: a newc archive whose only entry is the trailer. The
# kernel unpacks it, finds no /init, and falls through to root= as usual.
#
# DO NOT DELETE THIS FILE, and do not "tidy it up" as an empty leftover: without
# an -initrd, \`measure\` stops matching the guest and the reason is not obvious.
if [ ! -f "$DCU_INITRD" ]; then
    python3 - "$DCU_INITRD" <<'PY'
import sys
# 110-byte newc header (magic + 13 zeroed 8-hex-digit fields), the trailer name,
# and two NULs. Timestamps and uids are the zeros above, so the bytes are fixed.
open(sys.argv[1], 'wb').write(b'070701' + b'00000000' * 13 + b'TRAILER!!!' + b'\0\0')
PY
    echo "  initrd   generated $DCU_INITRD (\$(stat -c %s "$DCU_INITRD") bytes)"
else
    echo "  initrd   $DCU_INITRD (\$(stat -c %s "$DCU_INITRD") bytes)"
fi
EOF
}

# The DCU base is a shared cache, not instance state: one overlay on the read-only
# base image with the kata kernel's modules and firmware added, plus one fstab
# edit. Every DCU instance layers on it, which is why it is built once and reused
# and why rebuilding it under a running instance is refused - writing to a qcow2
# that other images have as a backing file corrupts all of them at once.
ensure_dcu_base() {
    local force="${1:-}"

    echo "==> DCU base image"
    host_script <<EOF
set -e

stamp_ok() {
    [ -f "$DCU_BASE_STAMP" ] || return 1
    grep -qx "recipe=$DCU_BASE_RECIPE" "$DCU_BASE_STAMP" || return 1
    grep -qx "kata_rootfs=$KATA_ROOTFS" "$DCU_BASE_STAMP" || return 1
    grep -qx "kata_rootfs_size=\$(stat -c %s "$KATA_ROOTFS" 2>/dev/null)" "$DCU_BASE_STAMP" || return 1
    grep -qx "kata_rootfs_mtime=\$(stat -c %Y "$KATA_ROOTFS" 2>/dev/null)" "$DCU_BASE_STAMP" || return 1
    grep -qx "kata_kernel_version=$KATA_KERNEL_VERSION" "$DCU_BASE_STAMP" || return 1
    grep -qx "oe_base=$HOST_BASE_DISK" "$DCU_BASE_STAMP" || return 1
    grep -qx "oe_base_size=\$(stat -c %s "$HOST_BASE_DISK" 2>/dev/null)" "$DCU_BASE_STAMP" || return 1
}

if [ "$force" != force ] && [ -f "$DCU_BASE_DISK" ] && stamp_ok; then
    echo "  reusing $DCU_BASE_DISK (built from these kata assets)"
    exit 0
fi

[ -f "$KATA_ROOTFS" ] || { echo "  FAIL kata root filesystem missing: $KATA_ROOTFS" >&2; exit 1; }
[ -f "$KATA_KERNEL" ] || { echo "  FAIL kata kernel missing: $KATA_KERNEL" >&2; exit 1; }

# Refuse to rebuild while anything has it open. The stamp covers the case where
# the source assets changed; this covers the case where the base is in use right
# now, and both have to hold before the old file is replaced. Asked by looking for
# open file descriptors rather than with qemu-img, because qemu-img would need the
# image lock - which a running guest holds - and this host's qemu-img has no
# force-share option to override it with. A running guest keeps its backing file
# open for reads, so the base shows up here whenever an overlay is in use.
holders=""
for fd in /proc/[0-9]*/fd/*; do
    [ -e "\$fd" ] || continue
    [ "\$(readlink "\$fd" 2>/dev/null)" = "$DCU_BASE_DISK" ] || continue
    pid=\${fd#/proc/}; pid=\${pid%%/*}
    holders="\$holders \$pid:\$(tr '\0' ' ' < /proc/\$pid/cmdline 2>/dev/null | cut -c1-60)"
done
if [ -n "\$holders" ]; then
    echo "  FAIL $DCU_BASE_DISK is open, so something is using it as a backing file:" >&2
    for h in \$holders; do echo "         \$h" >&2; done
    echo "  rebuilding it now would corrupt those guests. Stop them first." >&2
    exit 1
fi

stage=/var/tmp/dcu-stage
tmp="$DCU_BASE_DISK.tmp.\$\$"
trap 'rm -f "\$tmp"' EXIT
mkdir -p "\$stage"

echo "  building from $KATA_ROOTFS"
qemu-img create -f qcow2 -F qcow2 -b "$HOST_BASE_DISK" "\$tmp" >/dev/null

# Export the module tree and the versioned firmware directory. tar-out/tar-in
# rather than copy-in: both trees contain symlinks and the module index files
# (modules.dep, modules.alias, modules.builtin) have to arrive byte for byte, so
# that no depmod has to run on the host and no unrelated variable is introduced.
# The firmware has to land under /lib/firmware/<kernel release>/ - that is the
# versioned path the kernel searches first - and the module stack will not come up
# without it.
#
# tar-out packs the *contents* of the directory it is given, with member names
# prefixed ./, so it does not carry the directory itself. tar-in therefore has to
# target the directory, not its parent: tar-in ... /lib/modules would scatter
# modules.alias and updates/ directly into /lib/modules, and modprobe would then
# find no such module. mkdir-p first because tar-in does not create its target.
guestfish --ro -a "$KATA_ROOTFS" -i tar-out "/lib/modules/$KATA_KERNEL_VERSION" "\$stage/modules.tar"
guestfish --ro -a "$KATA_ROOTFS" -i tar-out "/lib/firmware/$KATA_KERNEL_VERSION" "\$stage/firmware.tar"
guestfish --rw -a "\$tmp" -i mkdir-p "/lib/modules/$KATA_KERNEL_VERSION"
guestfish --rw -a "\$tmp" -i mkdir-p "/lib/firmware/$KATA_KERNEL_VERSION"
guestfish --rw -a "\$tmp" -i tar-in "\$stage/modules.tar" "/lib/modules/$KATA_KERNEL_VERSION"
guestfish --rw -a "\$tmp" -i tar-in "\$stage/firmware.tar" "/lib/firmware/$KATA_KERNEL_VERSION"

# The kata kernel has no VFAT, FAT or NLS support at all, so the base image's
# /boot entry - the vfat ESP - can never mount. Left alone that fails
# local-fs.target and drops the guest into emergency mode instead of a login
# prompt. nofail keeps the entry working for the base image's own kernels while
# making it non-fatal here. Only this overlay is edited; the read-only base image
# is untouched, so the other kernel keeps its /boot.
guestfish --ro -a "\$tmp" -i cat /etc/fstab > "\$stage/fstab"
if grep -qE '^[^#[:space:]]+[[:space:]]+/boot[[:space:]]' "\$stage/fstab"; then
    python3 - "\$stage/fstab" <<'PY'
import sys
path = sys.argv[1]
out = []
for line in open(path):
    f = line.split()
    if len(f) >= 4 and not line.lstrip().startswith('#') and f[1] == '/boot':
        opts = f[3].split(',')
        if 'nofail' not in opts:
            opts.append('nofail')
            f[3] = ','.join(opts)
            line = '\t'.join(f[:4]) + ('\t' + ' '.join(f[4:]) if f[4:] else '') + '\n'
    out.append(line)
open(path, 'w').writelines(out)
PY
    guestfish --rw -a "\$tmp" -i upload "\$stage/fstab" /etc/fstab
    echo "  /boot marked nofail"
else
    echo "  WARN no /boot entry in fstab; the guest may still stop at emergency mode" >&2
fi

# Atomic: either the old base or the new one is in place, never a half-written one.
mv -f "\$tmp" "$DCU_BASE_DISK"
trap - EXIT
rm -f "\$stage/modules.tar" "\$stage/firmware.tar" "\$stage/fstab"

{
    echo "recipe=$DCU_BASE_RECIPE"
    echo "kata_rootfs=$KATA_ROOTFS"
    echo "kata_rootfs_size=\$(stat -c %s "$KATA_ROOTFS")"
    echo "kata_rootfs_mtime=\$(stat -c %Y "$KATA_ROOTFS")"
    echo "kata_kernel_version=$KATA_KERNEL_VERSION"
    echo "oe_base=$HOST_BASE_DISK"
    echo "oe_base_size=\$(stat -c %s "$HOST_BASE_DISK")"
    echo "built=\$(date -Is)"
} > "$DCU_BASE_STAMP"

echo "  built $DCU_BASE_DISK"
echo "  NOTE any overlay built on the previous base is now stale and must be recreated"
EOF
}

# The hycu stack is what makes the DCU usable, and it lives on the DCU base rather
# than in the base image. udev should load it by module alias once the device
# appears, but do not depend on that: load it explicitly and then report whether a
# driver actually took the device.
#
# Returns 0 if a driver bound the DCU, 1 otherwise, so callers can decide what an
# unbound DCU means - but it prints its findings either way, and nothing here
# should abort a command. Call it as `ensure_dcu_driver || true` where the answer
# does not matter.
ensure_dcu_driver() {
    local out rc=0
    out=$(guest_script <<'GUEST'
# Find the DCU by vendor:device, never by slot: it is 00:04.0 under the stock
# machine type and 01:00.0 behind a q35 root port.
dcu=""
for d in /sys/bus/pci/devices/*; do
    [ "$(cat "$d/vendor" 2>/dev/null)" = 0x1d94 ] || continue
    [ "$(cat "$d/device" 2>/dev/null)" = 0x6211 ] || continue
    dcu="$d"
done

if [ -z "$dcu" ]; then
    echo "  DCU  not enumerated in the guest"
    exit 1
fi
echo "  DCU  $(basename "$dcu")"

if ! lsmod | grep -q '^hycu '; then
    modprobe hycu 2>&1 | sed 's/^/  modprobe: /' || true
fi

# Loading the modules is not the same as a driver taking the device; give it a
# moment, the probe is not instant.
drv=""
for i in $(seq 1 20); do
    drv=$(basename "$(readlink -f "$dcu/driver" 2>/dev/null)" 2>/dev/null)
    [ "$drv" = hycu ] && break
    sleep 3
done

echo "  driver ${drv:-<none>}"
for n in /dev/kfd /dev/dri/card0 /dev/dri/renderD128; do
    [ -e "$n" ] && ls -l "$n" | sed 's/^/  /'
done
if [ "$drv" = hycu ]; then
    echo "  DCU  bound"
    exit 0
fi
echo "  DCU  not bound: hycu did not complete its probe. Recent driver log:"
dmesg 2>/dev/null | grep -i hycu | tail -8 | sed 's/^/  | /'
exit 1
GUEST
) || rc=$?
    [ -z "$out" ] || printf '%s\n' "$out"
    return $rc
}

vm_running() {
    local pid
    pid=$(vm_pid)
    [ -n "$pid" ] || return 1
    host "[ -d /proc/$pid ]" 2>/dev/null
}

# Read the guest address from inside the guest over the serial console. The guest
# is addressed by an external DHCP server, so when the host has never exchanged
# traffic with it this is the only way to learn the lease.
discover_ip_via_console() {
    local out i waited=0

    # Wait for a login prompt before typing anything. The handshake below is a
    # fixed sequence of sleeps, so whatever is typed before the prompt appears is
    # simply lost, and a DCU guest needs roughly 70-90s to reach it against about
    # 20s plain. Waiting on the console log instead of sleeping blindly also makes
    # the common case immediate. The log is truncated at launch, so a prompt in it
    # always belongs to the current boot.
    for i in $(seq 1 $((GUEST_BOOT_WAIT / 3))); do
        if host "grep -q 'login:' '$HOST_CONSOLE_LOG' 2>/dev/null"; then
            break
        fi
        sleep 3
        waited=$((waited + 3))
    done
    if [ "$waited" -ge "$GUEST_BOOT_WAIT" ]; then
        echo "  no login prompt after ${GUEST_BOOT_WAIT}s; see $HOST_CONSOLE_LOG" >&2
    fi

    out=$(host "{ printf '\n'; sleep 2; printf 'root\n'; sleep 4; printf '${CSV2_GUEST_PASS}\n'; sleep 5; printf 'hostname -I\n'; sleep 3; } | timeout 45 socat - UNIX-CONNECT:${HOST_SERIAL} 2>&1" 2>/dev/null \
        | sed -e 's/\x1b\[[0-9;?]*[a-zA-Z]//g' -e 's/\r//g')
    # Take the last IPv4 in the stream: the login banner may print one earlier,
    # and the `hostname -I` answer is what we actually asked for.
    printf '%s\n' "$out" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '^127\.' | tail -1
}

# Resolve the guest address. A freshly created instance is addressed by the LAN
# DHCP server, so its address is unknown until the guest boots.
resolve_guest_ip() {
    if [ -n "$VM_IP" ]; then
        return 0
    fi

    local mac_lc ip i
    mac_lc=$(printf '%s' "$VM_MAC" | tr 'A-Z' 'a-z')

    # Fast path: the bridge neighbour table. It only holds an entry once the host
    # has exchanged traffic with the guest, so this often misses on a fresh boot.
    for i in $(seq 1 6); do
        ip=$(host "ip neigh show dev $HOST_BRIDGE | grep -i '$mac_lc' | awk '{print \$1}' | head -1" 2>/dev/null | tr -d '\r' | head -1)
        if [ -n "$ip" ]; then
            VM_IP="$ip"
            return 0
        fi
        sleep 5
    done

    ip=$(discover_ip_via_console)
    if [ -n "$ip" ]; then
        VM_IP="$ip"
        return 0
    fi
    return 1
}

# ------------------------------- commands ------------------------------------

cmd_deps() {
    host_script <<EOF
set -u
fail=0

row() { # <path> <role> <required|optional>
    local p="\$1" role="\$2" req="\$3" status
    if [ -e "\$p" ]; then
        if [ -f "\$p" ]; then status="ok (\$(du -hL "\$p" 2>/dev/null | cut -f1))"; else status="ok"; fi
    elif [ "\$req" = required ]; then
        status="MISSING"; fail=1
    else
        status="absent"
    fi
    printf "  %-56s  %-36s  %s\n" "\$p" "\$role" "\$status"
}

echo "host side - required before 'up':"
row "$HOST_BASE_DISK" "guest base image (backing, read-only)" required
row "$HOST_OVMF" "confidential-guest firmware (pflash)" required
row /dev/sev "PSP device; memory encryption" required
row /etc/qemu/bridge.conf "allow-list for QEMU bridge attach" required

if ip link show $HOST_BRIDGE >/dev/null 2>&1; then
    if grep -qE "^[[:space:]]*allow[[:space:]]+$HOST_BRIDGE\$" /etc/qemu/bridge.conf 2>/dev/null; then
        printf "  %-56s  %-36s  %s\n" "$HOST_BRIDGE" "LAN uplink + guest DHCP lease" "ok (allowed)"
    else
        printf "  %-56s  %-36s  %s\n" "$HOST_BRIDGE" "LAN uplink + guest DHCP lease" "NOT ALLOWED"; fail=1
    fi
else
    printf "  %-56s  %-36s  %s\n" "$HOST_BRIDGE" "LAN uplink + guest DHCP lease" "MISSING"; fail=1
fi

echo
echo "instance disk - created by 'up' if absent:"
row "$HOST_DISK" "writable overlay for this instance" optional

if [ "$CSV2_DCU_ON" = 1 ]; then
    echo
    echo "DCU mode - required for this mode only. The kernel and initramfs are the"
    echo "measured-boot inputs here, because this mode boots them:"
    row "$HOST_BACKING" "shared DCU base; 'up' builds it if absent" optional
    row "$KATA_KERNEL" "kata kernel; hashed into the launch measurement" required
    row "$KATA_ROOTFS" "source of the hycu modules and firmware" required
    row "$HOST_QEMU" "QEMU build that can drive the DCU" required
    row "$DCU_INITRD" "empty initramfs; hashed into the launch measurement" optional
    for t in guestfish qemu-img; do
        p=\$(command -v "\$t" 2>/dev/null || true)
        row "\${p:-/nonexistent/\$t}" "needed to build the DCU images" required
    done
else
    echo
    echo "measured boot - extracted from the base image by 'up' if absent:"
    row "$HOST_KERNEL" "guest kernel; hashed into the launch measurement" optional
    row "$HOST_INITRD" "guest initramfs; hashed into the launch measurement" optional
fi

echo
if [ "$CSV2_DCU_ON" = 1 ]; then
    printf "  %-56s  %-36s  %s\n" "csv-guest" "provides /dev/csv-guest" "built into the kata kernel"
else
    echo "guest side - already inside the base image, nothing to stage:"
    printf "  %-56s  %-36s  %s\n" "csv-guest.ko.xz" "provides /dev/csv-guest" "in base image"
fi

echo
echo "verification only - needed by 'verify' and 'measure', not by 'up':"
row "$SMOKE_BIN" "attestation smoke test" optional
row "$CERT_DIR/hrk.cert" "Hygon root key (HRK) cert" optional
row "$CERT_DIR/hsk_cek.cert" "Hygon endorsement (HSK/CEK) cert" optional
row "$MEASURE_TOOL" "computes the expected launch measurement" optional
row "$GET_ATTESTATION_BIN" "fetches the report the guest actually gets" optional

echo
if [ "\$fail" = 0 ]; then
    echo "result: required host files present"
else
    echo "result: required host files MISSING" >&2
fi
exit \$fail
EOF
}

preflight() {
    echo "==> preflight"
    host_script <<EOF
set -u
fail=0

# Memory encryption requires the PSP device on the host.
if [ -c /dev/sev ]; then
    echo "  ok   /dev/sev present"
else
    echo "  FAIL /dev/sev missing (memory encryption unavailable)"; fail=1
fi

# The firmware must have enabled CSV2, otherwise QEMU cannot launch a CSV2 guest.
if dmesg 2>/dev/null | grep -q "CSV2 enabled"; then
    echo "  ok   firmware reports CSV2 enabled"
else
    echo "  WARN no 'CSV2 enabled' in dmesg"
fi

if ip link show $HOST_BRIDGE >/dev/null 2>&1; then
    echo "  ok   bridge $HOST_BRIDGE up"
else
    echo "  FAIL bridge $HOST_BRIDGE missing"; fail=1
fi

# QEMU refuses to attach a bridge unless it is allow-listed.
if grep -qE "^[[:space:]]*allow[[:space:]]+$HOST_BRIDGE\$" /etc/qemu/bridge.conf 2>/dev/null; then
    echo "  ok   $HOST_BRIDGE allowed in /etc/qemu/bridge.conf"
else
    echo "  FAIL $HOST_BRIDGE not allowed in /etc/qemu/bridge.conf"; fail=1
fi

if [ -f "$HOST_BASE_DISK" ]; then
    echo "  ok   base image $HOST_BASE_DISK"
else
    echo "  FAIL base image $HOST_BASE_DISK missing"; fail=1
fi

if [ -f "$HOST_OVMF" ]; then
    echo "  ok   firmware $HOST_OVMF"
else
    echo "  FAIL firmware $HOST_OVMF missing"; fail=1
fi

# A fixed MAC is the instance's identity, so make sure nothing else already uses it.
if ip neigh show dev $HOST_BRIDGE 2>/dev/null | grep -qi "$VM_MAC"; then
    echo "  WARN MAC $VM_MAC already present on $HOST_BRIDGE (reusing an instance?)"
else
    echo "  ok   MAC $VM_MAC not in use"
fi

# Do not take an address that something else already answers on. Skipped when the
# address is left to DHCP, since it is not known until the guest boots.
if [ -n "$VM_IP" ]; then
    if ping -c 1 -W 2 $VM_IP >/dev/null 2>&1; then
        echo "  FAIL $VM_IP already responds (address collision)"; fail=1
    else
        echo "  ok   $VM_IP is free"
    fi
else
    echo "  --   guest IP left to DHCP, will be discovered after boot"
fi

# DCU mode boots a different kernel from a different root filesystem with a
# different QEMU, so check all three here rather than failing halfway through a
# launch. The disk images are built by \`up\`, so they are not checked for existence.
if [ "$CSV2_DCU_ON" = 1 ]; then
    if [ -f "$KATA_KERNEL" ]; then
        echo "  ok   kata kernel $KATA_KERNEL"
    else
        echo "  FAIL kata kernel missing: $KATA_KERNEL"; fail=1
    fi
    if [ -f "$KATA_ROOTFS" ]; then
        echo "  ok   kata root filesystem $KATA_ROOTFS"
    else
        echo "  FAIL kata root filesystem missing: $KATA_ROOTFS"; fail=1
    fi
    if [ -x "$HOST_QEMU" ]; then
        echo "  ok   QEMU $HOST_QEMU"
    else
        echo "  FAIL QEMU missing or not executable: $HOST_QEMU"; fail=1
    fi
    for t in guestfish qemu-img; do
        if command -v "\$t" >/dev/null 2>&1; then
            echo "  ok   \$t"
        else
            echo "  FAIL \$t not found (needed to build the DCU base image)"; fail=1
        fi
    done
    free_mb=\$(df -Pk "$HOST_DISK_DIR" 2>/dev/null | awk 'NR==2 {print int(\$4 / 1024)}')
    if [ "\${free_mb:-0}" -lt 2048 ]; then
        echo "  FAIL only \${free_mb:-unknown}MB free in $HOST_DISK_DIR"; fail=1
    else
        echo "  ok   \${free_mb}MB free in $HOST_DISK_DIR"
    fi
fi

# Passthrough devices. QEMU's own error for these does not name the device, and
# a group member left unlisted is a silent isolation hole, so check both here.
for d in $VFIO_DEVICES; do
    p=/sys/bus/pci/devices/0000:\$d
    [ -e "\$p" ] || p=/sys/bus/pci/devices/\$d
    if [ ! -e "\$p" ]; then
        echo "  FAIL passthrough device \$d does not exist"; fail=1; continue
    fi
    drv=\$(basename "\$(readlink -f \$p/driver 2>/dev/null)" 2>/dev/null)
    if [ "\$drv" != vfio-pci ]; then
        echo "  FAIL \$d is bound to \${drv:-no driver}, not vfio-pci"
        # No sysfs recipes here, deliberately. This card punishes improvisation: once
        # the vendor module's probe (hycu_pci_fixup_header) has deadlocked on the
        # device lock, unbind and rmmod block behind it too, and remove + rescan is
        # what triggers that deadlock - it wedges the card until the host is rebooted.
        # See the DCU section in the header. Name the two recovered paths, and leave
        # anything beyond them to the vendor.
        echo "       the card has to be on vfio-pci before a guest can be given it, and"
        echo "       moving it there by hand is not safe - unbind and rmmod can block on"
        echo "       the device lock, and remove + rescan deadlocks the vendor module's"
        echo "       probe until the host is rebooted. Recovery, in order:"
        echo "         systemctl start dcu-bind-vfio.service   # then re-run this command"
        echo "         reboot                                  # if it is already wedged"
        echo "       Beyond those two, leave it to the vendor."
        fail=1; continue
    fi
    grp=\$(basename "\$(readlink -f \$p/iommu_group 2>/dev/null)")
    siblings=\$(ls /sys/kernel/iommu_groups/\$grp/devices 2>/dev/null | wc -l)
    if [ "\$siblings" != 1 ]; then
        echo "  WARN \$d shares IOMMU group \$grp with \$((siblings - 1)) other device(s);"
        echo "       every member has to be passed through together or not at all"
    fi
    echo "  ok   \$d bound to vfio-pci (iommu group \$grp)"
done

# An overlay is only bootable by the mode whose backing file it was built on. The
# mode picks the name, but a name proves nothing about what is behind it - someone
# can build an overlay by hand, or point CSV2_DISK at one - so check the chain and
# refuse rather than boot the wrong thing.
if [ -f "$HOST_DISK" ] && ! qemu-img info --backing-chain "$HOST_DISK" 2>/dev/null | grep -qx "image: $HOST_BACKING"; then
    echo "  FAIL $HOST_DISK does not have $HOST_BACKING in its backing chain"
    echo "       it was built for the other mode; delete it, or set CSV2_DISK"
    fail=1
fi

exit \$fail
EOF
}

cmd_up() {
    if vm_running; then
        echo "$VM_NAME already running (pid $(vm_pid))"
        return 0
    fi

    preflight

    # Before the overlay, because the overlay's backing file is the DCU base.
    if use_dcu; then
        ensure_dcu_base
    fi

    echo "==> overlay disk"
    host_script <<EOF
set -e
if [ -f "$HOST_DISK" ]; then
    echo "  reusing existing overlay (guest state preserved): $HOST_DISK"
else
    # Fresh overlay on the read-only base image.
    qemu-img create -f qcow2 -F qcow2 -b "$HOST_BACKING" "$HOST_DISK"
    echo "  created overlay: $HOST_DISK"
fi
# Truncated so that a login prompt in the console log always belongs to this boot:
# the address discovery waits for one, and would otherwise match the previous boot.
: > "$HOST_CONSOLE_LOG"
EOF

    echo "==> measured-boot images"
    ensure_boot_images

    # Built here rather than inline so an empty list contributes no argument at
    # all; the continuation line it lands on then collapses to nothing.
    local vfio_args="" d n=0
    for d in $VFIO_DEVICES; do
        if use_dcu; then
            # q35 puts the DCU behind an explicit root port. Behind the root port
            # the hycu driver gets through its PCIe initialisation - under the
            # default machine type it spins forever at the same point, and putting
            # the device on the root complex instead makes QEMU itself segfault.
            vfio_args="$vfio_args -device pcie-root-port,id=rp$n,bus=pcie.0 -device vfio-pci,host=$d,bus=rp$n"
        else
            vfio_args="$vfio_args -device vfio-pci,host=$d"
        fi
        n=$((n + 1))
    done

    # The disk bus and the machine type are the other two mode differences. Both
    # are built as strings so that the plain mode's -hda line survives verbatim.
    local disk_args machine_args
    if use_dcu; then
        # -hda is IDE. The kata kernel has no ATA support, so it cannot see it.
        disk_args="-drive file=$HOST_DISK,if=virtio,format=qcow2"
        # kernel_irqchip=split is what the kata runtime pairs with q35.
        machine_args="-machine q35,accel=kvm,kernel_irqchip=split,confidential-guest-support=sev0"
    else
        disk_args="-hda \"$HOST_DISK\""
        machine_args="-machine memory-encryption=sev0"
    fi

    echo "==> launching $VM_NAME (policy=$VM_POLICY -> CSV2, ${VM_VCPUS} vCPU, ${VM_MEM_MB}MB)"
    [ -n "$vfio_args" ] && echo "    passthrough:$vfio_args"

    # VNC is not in every QEMU build: the Hygon kata build that DCU mode uses is
    # compiled without it and rejects -vnc as an invalid option, which fails the
    # launch outright. Ask the binary rather than assume, so a build that has VNC
    # keeps it and one that does not still starts.
    #
    # The answer is read out of the captured help text instead of being piped into
    # `grep -q`: grep -q exits at the first match, the writer then takes SIGPIPE,
    # and under pipefail that makes the pipeline fail - so every build, VNC or not,
    # would look like it had none. An empty CSV2_VNC_DISPLAY turns VNC off.
    local vnc_args="" qemu_help
    if [ -n "$HOST_VNC_DISPLAY" ]; then
        qemu_help=$($HOST_QEMU -help 2>&1 || true)
        case "$qemu_help" in
            *"-vnc "*) vnc_args="-vnc 127.0.0.1:$HOST_VNC_DISPLAY" ;;
            *) echo "    NOTE $HOST_QEMU was built without VNC; starting without -vnc" >&2 ;;
        esac
    fi

    host_script <<EOF
set -e
$HOST_QEMU -name $VM_NAME \\
    --enable-kvm -cpu host -smp $VM_VCPUS -m $VM_MEM_MB \\
    -kernel "$HOST_KERNEL" \\
    -initrd "$HOST_INITRD" \\
    -append "$VM_APPEND" \\
    $disk_args \\
    -drive if=pflash,format=raw,unit=0,file=$HOST_OVMF,readonly=on \\
    -qmp tcp:127.0.0.1:$HOST_QMP_PORT,server,nowait \\
    $vnc_args \\
    -object sev-guest,id=sev0,policy=$VM_POLICY,cbitpos=$VM_CBITPOS,reduced-phys-bits=$VM_REDUCED_PHYS_BITS,kernel-hashes=on \\
    $machine_args \\
    -netdev bridge,br=$HOST_BRIDGE,id=net0$([ "$CSV2_DCU_ON" = 1 ] && printf ',helper=/usr/libexec/qemu-bridge-helper') \\
    -device virtio-net-pci,netdev=net0,mac=$VM_MAC,romfile= \\
    $vfio_args \\
    -chardev socket,id=ser0,path=$HOST_SERIAL,server=on,wait=off,logfile=$HOST_CONSOLE_LOG \\
    -serial chardev:ser0 \\
    -daemonize -pidfile $HOST_PIDFILE
EOF

    if ! vm_running; then
        echo "launch failed; host console log tail:" >&2
        host "tail -20 '$HOST_CONSOLE_LOG' 2>/dev/null | tr -d '\r'" >&2 || true
        return 1
    fi
    echo "  started, pid $(vm_pid)"

    if [ -z "$VM_IP" ]; then
        echo "==> discovering guest address (MAC $VM_MAC)"
        if ! resolve_guest_ip; then
            echo "  no neighbour entry for $VM_MAC on $HOST_BRIDGE; check $HOST_CONSOLE_LOG" >&2
            return 1
        fi
    fi
    echo "  guest address: $VM_IP"

    echo "==> waiting for guest ssh"
    local i
    for i in $(seq 1 36); do
        if host "timeout 3 bash -c 'echo > /dev/tcp/$VM_IP/22'" 2>/dev/null; then
            echo "  guest reachable (after ~$((i * 10))s)"
            break
        fi
        sleep 10
    done
    if ! host "timeout 3 bash -c 'echo > /dev/tcp/$VM_IP/22'" 2>/dev/null; then
        echo "  guest ssh did not come up; check $HOST_CONSOLE_LOG" >&2
        return 1
    fi

    echo "==> loading csv-guest module in guest"
    ensure_csv_guest_device

    if use_dcu; then
        echo "==> DCU driver in guest"
        ensure_dcu_driver || true
    fi

    echo "==> done"
    echo "  name  $VM_NAME"
    echo "  guest $VM_IP (mac $VM_MAC)"
    echo "  boot  measured: OVMF + cmdline/initrd/kernel hash table"
    if use_dcu; then
        echo "  mode  DCU passthrough: kernel $KATA_KERNEL_VERSION, disk $HOST_DISK"
    fi
    echo "  stop  $(basename "$0") down   [with CSV2_VM_NAME=$VM_NAME]"
    echo "  check $(basename "$0") measure [with CSV2_VM_NAME=$VM_NAME]"
}

cmd_status() {
    if ! vm_running; then
        echo "$VM_NAME is not running"
        return 1
    fi

    # An instance that was not pinned to an address still needs discovery.
    resolve_guest_ip 2>/dev/null || true

    host_script <<EOF
set -u
pid=\$(cat $HOST_PIDFILE)
printf "process   pid %s  %s\n" "\$pid" "\$(ps -o etime=,pcpu=,rss= -p \$pid | awk '{printf "up %s  cpu %s%%  rss %.1fGB", \$1, \$2, \$3/1048576}')"

# Ask QEMU directly whether the guest is actually encrypted, rather than trusting
# the launch arguments.
python3 - <<'PY'
import json, socket
s = socket.create_connection(('127.0.0.1', $HOST_QMP_PORT), timeout=8)
f = s.makefile('rw')
json.loads(f.readline())
s.sendall(b'{"execute":"qmp_capabilities"}\n'); f.readline()

def cmd(name):
    s.sendall((json.dumps({'execute': name}) + '\n').encode())
    while True:
        line = f.readline()
        if not line:
            return {}
        m = json.loads(line)
        if 'return' in m:
            return m['return']
        if 'error' in m:
            return {}

sev = cmd('query-sev')
if sev.get('enabled'):
    kind = {5: 'CSV2', 7: 'CSV2', 69: 'CSV3'}.get(sev.get('policy'), 'policy=%s' % sev.get('policy'))
    print('encryption  %s (%s, firmware handle=%s)' % (kind, sev.get('state'), sev.get('handle')))
else:
    print('encryption  DISABLED - guest memory is not encrypted!')
print('vcpus       %d' % len(cmd('query-cpus-fast')))
PY

if [ -n "$VM_IP" ] && ping -c 1 -W 2 $VM_IP >/dev/null 2>&1; then
    echo "network     $VM_IP reachable (mac $VM_MAC)"
elif [ -n "$VM_IP" ]; then
    echo "network     $VM_IP unreachable"
else
    echo "network     address not discovered yet (mac $VM_MAC)"
fi
echo "console     $HOST_CONSOLE_LOG"
EOF

    # Informational, and deliberately not part of the exit status: whether a
    # driver took the DCU says nothing about whether the guest is a valid CSV2
    # guest, and `up` should not have failed for it either.
    if use_dcu; then
        echo
        ensure_dcu_driver || true
    fi
}

cmd_verify() {
    vm_running || { echo "$VM_NAME is not running" >&2; return 1; }
    resolve_guest_ip || { echo "could not discover the guest address for $VM_MAC" >&2; return 1; }
    # Do not assume a previous `up` left the module loaded; a reboot clears it.
    ensure_csv_guest_device

    host_script <<EOF
set -e
[ -x "$SMOKE_BIN" ] || { echo "smoke binary not found: $SMOKE_BIN" >&2; exit 1; }
export SSHPASS="$CSV2_GUEST_PASS"
# stdin is closed on both hops: this block arrives on the host as \`bash -s\`, so
# a command that reads stdin would consume the rest of the script.
sshpass -e scp -o StrictHostKeyChecking=accept-new "$SMOKE_BIN" root@$VM_IP:/root/ </dev/null >/dev/null
# Chain verification needs the Hygon HRK/HSK-CEK certs alongside the binary.
if [ -f "$CERT_DIR/hrk.cert" ] && [ -f "$CERT_DIR/hsk_cek.cert" ]; then
    sshpass -e scp -o StrictHostKeyChecking=accept-new \\
        "$CERT_DIR/hrk.cert" "$CERT_DIR/hsk_cek.cert" root@$VM_IP:/root/ </dev/null >/dev/null
    echo "certs: copied from $CERT_DIR"
else
    echo "certs: not found under $CERT_DIR, report signature only" >&2
fi
sshpass -e ssh -n -o StrictHostKeyChecking=accept-new root@$VM_IP \\
    '/root/$(basename $SMOKE_BIN) -verify-chain -out /root/smoke-chain.json; echo "EXIT=\$?"; cat /root/smoke-chain.json'
EOF

    # The DCU result is reported, not asserted: a DCU that did not bind is a fact
    # about the hardware, and it does not make the attestation chain invalid. The
    # smoke test's exit status above is what `verify` returns.
    if use_dcu; then
        echo
        if ! ensure_dcu_driver; then
            echo "verify: attestation chain checked; the DCU is NOT bound (see above)" >&2
        fi
    fi
}

# The launch measurement is a pure function of host-side files, so it can be
# computed without booting anything. Comparing that value against the one a
# running guest actually reports is what ties the report to this exact firmware,
# command line, initramfs and kernel - and nothing else.
cmd_measure() {
    local expected_b64 expected_hex

    # DCU mode's kernel is a host file and its initramfs is generated, so the pair
    # can be prepared here. The plain mode's pair has to be copied out of the base
    # image, which is `up`'s job - so it keeps telling the caller to run `up`.
    if use_dcu; then
        ensure_boot_images
    fi

    if ! expected_b64=$(host_script <<EOF
set -e
[ -f "$MEASURE_TOOL" ] || { echo "measure tool not found: $MEASURE_TOOL" >&2; exit 1; }
if [ ! -f "$HOST_KERNEL" ]; then
    echo "kernel not extracted yet: $HOST_KERNEL" >&2
    echo "run '$(basename "$0") up' once to copy it out of $HOST_BASE_DISK" >&2
    exit 1
fi
if [ ! -f "$HOST_INITRD" ]; then
    echo "initramfs not extracted yet: $HOST_INITRD" >&2
    echo "run '$(basename "$0") up' once to copy it out of $HOST_BASE_DISK" >&2
    exit 1
fi

# The tool hashes the command line from a file that holds the string plus the
# trailing newline QEMU records before hashing it, so reproduce that exactly.
cmdline=\$(mktemp)
trap 'rm -f "\$cmdline"' EXIT
printf '%s\n' "$VM_APPEND" > "\$cmdline"

# Run it through python3 rather than executing it: its shebang names a platform
# interpreter that is not installed on every host.
python3 "$MEASURE_TOOL" --ovmf "$HOST_OVMF" --kernel "$HOST_KERNEL" --initrd "$HOST_INITRD" --cmdline "\$cmdline"
EOF
); then
        return 1
    fi
    expected_hex=$(printf '%s' "$expected_b64" \
        | python3 -c 'import base64,sys; print(base64.b64decode(sys.stdin.read().strip()).hex())')

    echo "==> launch measurement of $VM_NAME"
    echo
    echo "expected  $expected_hex"
    echo "  inputs  OVMF     $HOST_OVMF"
    echo "          kernel   $HOST_KERNEL"
    echo "          initrd   $HOST_INITRD"
    echo "          cmdline  $VM_APPEND"

    if ! vm_running; then
        echo
        echo "instance is not running, so there is no report to compare against" >&2
        return 1
    fi
    resolve_guest_ip || { echo "could not discover the guest address for $VM_MAC" >&2; return 1; }
    ensure_csv_guest_device

    local report_out actual_hex actual_policy
    if ! report_out=$(host_script <<EOF
set -e
[ -x "$GET_ATTESTATION_BIN" ] || { echo "attestation tool not found: $GET_ATTESTATION_BIN" >&2; exit 1; }
export SSHPASS="$CSV2_GUEST_PASS"
# get-attestation writes ./report.cert beside itself, so run it from /root and
# pull the report back whole rather than trying to decode it over the wire.
# Both commands get their stdin explicitly closed: this block arrives on the
# host as \`bash -s\`, and anything reading stdin would otherwise swallow the
# rest of the script.
sshpass -e scp -o StrictHostKeyChecking=accept-new "$GET_ATTESTATION_BIN" root@$VM_IP:/root/ </dev/null >/dev/null
sshpass -e ssh -n -o StrictHostKeyChecking=accept-new root@$VM_IP \\
    'cd /root && ./$(basename "$GET_ATTESTATION_BIN") >/dev/null && cat report.cert' > /tmp/$VM_NAME.report

# The report masks its hash blocks and several scalar fields with ANonce, one
# 32-bit word at a time. Reading them raw yields plausible-looking garbage.
python3 - <<'PY'
import struct
raw = open('/tmp/$VM_NAME.report', 'rb').read()
if len(raw) < 0x9f4:
    raise SystemExit('report is %d bytes, want 0x9f4' % len(raw))
anonce = struct.unpack_from('<I', raw, 0x0bc)[0]
words = struct.unpack_from('<8I', raw, 0x090)
print(struct.pack('<8I', *[w ^ anonce for w in words]).hex())
print(struct.unpack_from('<I', raw, 0x0b0)[0] ^ anonce)
PY
EOF
); then
        return 1
    fi
    actual_hex=$(printf '%s\n' "$report_out" | sed -n '1p')
    actual_policy=$(printf '%s\n' "$report_out" | sed -n '2p')

    echo
    echo "actual    $actual_hex"
    [ -n "$actual_policy" ] && printf "  policy  0x%x\n" "$actual_policy"
    echo

    if [ "$actual_hex" = "$expected_hex" ]; then
        echo "MATCH - the report is bound to exactly these firmware, cmdline, initramfs and kernel files"
        return 0
    fi
    echo "MISMATCH - the running guest was not launched from the files listed above" >&2
    echo "  the report is bound to whatever the VM was booted with; change the" >&2
    echo "  kernel/initramfs/cmdline, then 'down' and 'up' to boot the new ones" >&2
    return 1
}

cmd_ssh() {
    vm_running || { echo "$VM_NAME is not running" >&2; return 1; }
    resolve_guest_ip || { echo "could not discover the guest address for $VM_MAC" >&2; return 1; }
    host env SSHPASS="$CSV2_GUEST_PASS" "sshpass -e ssh -o StrictHostKeyChecking=accept-new root@$VM_IP"
}

cmd_down() {
    local purge=0
    [ "${1:-}" = "--purge-disk" ] && purge=1

    if vm_running; then
        local pid
        pid=$(vm_pid)
        echo "==> stopping $VM_NAME (pid $pid)"

        # Prefer an ACPI shutdown so the guest unmounts its filesystems; killing
        # QEMU outright leaves the guest dirty.
        host_script <<EOF
python3 - <<'PY' 2>/dev/null || true
import json, socket
s = socket.create_connection(('127.0.0.1', $HOST_QMP_PORT), timeout=8)
f = s.makefile('rw')
json.loads(f.readline())
s.sendall(b'{"execute":"qmp_capabilities"}\n'); f.readline()
s.sendall(b'{"execute":"system_powerdown"}\n')
print('  sent ACPI powerdown')
PY
EOF

        local i
        for i in $(seq 1 60); do
            vm_running || break
            sleep 1
        done

        if vm_running; then
            echo "  guest did not power off, sending SIGTERM"
            host "kill $pid 2>/dev/null || true"
            for i in $(seq 1 15); do
                vm_running || break
                sleep 1
            done
        fi
        if vm_running; then
            echo "  still up, sending SIGKILL"
            host "kill -9 $pid 2>/dev/null || true"
            sleep 2
        fi
        if vm_running; then
            echo "  failed to stop pid $pid" >&2
            return 1
        fi
        echo "  stopped"
    else
        echo "$VM_NAME is not running"
    fi

    echo "==> cleaning runtime files"
    # These are recreated on the next boot; removing them only drops the console
    # history and the serial socket.
    host "rm -f '$HOST_PIDFILE' '$HOST_SERIAL'" && echo "  removed $HOST_PIDFILE, $HOST_SERIAL"

    if [ "$purge" = 1 ]; then
        echo "==> purging overlay disk"
        # Destructive: discards all guest state. The read-only base image is
        # untouched, so `up` can still build a fresh overlay afterwards.
        host "rm -f '$HOST_DISK'" && echo "  removed $HOST_DISK"
    else
        echo "  kept overlay disk: $HOST_DISK (use --purge-disk to delete)"
    fi

    # The DCU base is shared cache, not instance state: every DCU instance layers
    # on it, so purging one instance's overlay must not take it away.
    if use_dcu; then
        echo "  kept shared DCU base: $DCU_BASE_DISK (rebuild with '$(basename "$0") dcu-base')"
    fi
}

# Rebuild the shared DCU base from the current kata assets. `up` already rebuilds
# it when the assets it was built from have changed, but this forces it after any
# other change and shows the build output on its own.
cmd_dcu_base() {
    if ! use_dcu; then
        echo "dcu-base only applies to DCU mode; set CSV2_DCU=1" >&2
        return 1
    fi
    if vm_running; then
        echo "$VM_NAME is running; stop it first (down)" >&2
        return 1
    fi
    ensure_dcu_base force
}

# ---------------------------- the DCU test pod -------------------------------
#
# Three commands that drive a cluster over ssh. They share nothing with the QEMU
# commands above: no disks, no measurement, no libvirt. What the pod is, is the
# vendored template next to this script, and these commands never restate it - they
# read the fields they need out of that file, so the object that gets checked for and
# the object that gets applied cannot drift apart. That is the vendor's own design,
# kept because the failure it prevents is silent.
#
# Values reach the host through `host env`, which hands them to ssh as command-line
# words - so the remote shell parses them a second time, and anything with a space, a
# quote or a `$` in it would be split or expanded before the script ever ran. The two
# values that can hold arbitrary text are therefore base64-encoded; the rest are
# constrained to a charset that cannot be anything else, and are refused loudly rather
# than mangled quietly.

# Read one field out of the pod template. First match wins, and that matters: the
# template has a `name:` for the Pod and another for its Service.
#
# awk rather than the `sed -n ... | head -1` this was ported from. With pipefail set,
# a reader that exits early can hand the writer a SIGPIPE, which turns the whole
# substitution into a failure rather than a value. awk stops reading its own file, so
# there is no pipe to break. Same trap as the two documented under `pod-up`.
pod_field() {
    awk -v pattern="$1" '
        $0 ~ pattern {
            sub(pattern, "")
            gsub(/^[ \t]+|[ \t]+$/, "")
            print
            exit
        }' "$POD_TEMPLATE"
}

# Collect the template's fields plus the two values that are not written down in it.
# Sets globals, the way resolve_guest_ip does.
pod_facts() {
    [ -f "$POD_TEMPLATE" ] \
        || { echo "pod template $POD_TEMPLATE is missing" >&2; return 1; }

    POD_NAME="$(pod_field '^  name:')"
    POD_NODE_PORT="$(pod_field '^[ \t]*nodePort:' | tr -dc '0-9')"
    POD_RUNTIMECLASS="$(pod_field '^[ \t]*runtimeClassName:')"
    POD_IMAGE="$(pod_field '^[ \t]*image:')"

    [ -n "$POD_NAME" ]         || { echo "no metadata.name in $POD_TEMPLATE" >&2; return 1; }
    [ -n "$POD_NODE_PORT" ]    || { echo "no nodePort in $POD_TEMPLATE" >&2; return 1; }
    [ -n "$POD_RUNTIMECLASS" ] || { echo "no runtimeClassName in $POD_TEMPLATE" >&2; return 1; }
    [ -n "$POD_IMAGE" ]        || { echo "no container image in $POD_TEMPLATE" >&2; return 1; }

    # The template names the image the guest will pull; this script decides which one
    # it pushes. If they disagree the push succeeds, the pull times out, and nothing
    # in between says why.
    POD_IMAGE_LOCAL="$POD_REGISTRY/vllm:ubuntu-dtk"
    if [ "$POD_IMAGE" != "$POD_IMAGE_LOCAL" ]; then
        echo "the template and this script name different images:" >&2
        echo "  template: $POD_IMAGE" >&2
        echo "  script:   $POD_IMAGE_LOCAL   (CSV2_POD_REGISTRY=$POD_REGISTRY)" >&2
        return 1
    fi

    POD_SERVICE="${POD_NAME}-ssh"

    # See the note above: these travel as bare command-line words.
    case "$POD_NAMESPACE$POD_REGISTRY$POD_INITDATA$POD_IMAGE_UPSTREAM" in
        *[!A-Za-z0-9._:@/+-]*)
            echo "these must not contain spaces, quotes or shell metacharacters:" >&2
            echo "  CSV2_POD_NAMESPACE=$POD_NAMESPACE" >&2
            echo "  CSV2_POD_REGISTRY=$POD_REGISTRY" >&2
            echo "  CSV2_POD_INITDATA=$POD_INITDATA" >&2
            echo "  CSV2_POD_IMAGE_UPSTREAM=$POD_IMAGE_UPSTREAM" >&2
            return 1 ;;
    esac
}

cmd_pod_up() {
    local dry_run=0 skip_push=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run)   dry_run=1; shift ;;
            --skip-push) skip_push=1; shift ;;
            *) echo "pod-up: unknown argument $1" >&2; return 1 ;;
        esac
    done

    pod_facts || return 1

    # The pod's sshd password, and the only credential this script invents. The
    # template's two placeholders are substituted with sed, which reads & \ and | in
    # the replacement, so those three are refused rather than escaped.
    local pw="$POD_PASSWORD"
    if [ -z "$pw" ]; then
        # /dev/urandom read straight, then converted: no pipeline whose reader leaves
        # early, so pipefail has nothing to trip over. Hex cannot contain a character
        # sed would read.
        pw="$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    fi
    case "$pw" in
        *'&'*|*'\'*|*'|'*)
            echo "CSV2_POD_PASSWORD must not contain & \\ or | - sed substitutes it" >&2
            return 1 ;;
    esac
    [ "${#pw}" -ge 8 ] || echo "  note: that password is under 8 characters"

    echo "==> DCU test pod $POD_NAMESPACE/$POD_NAME"

    host env \
        CSV2POD_TEMPLATE_B64="$(base64 -w0 < "$POD_TEMPLATE")" \
        CSV2POD_PASSWORD_B64="$(printf '%s' "$pw" | base64 -w0)" \
        CSV2POD_NAMESPACE="$POD_NAMESPACE" \
        CSV2POD_POD_NAME="$POD_NAME" \
        CSV2POD_NODE_PORT="$POD_NODE_PORT" \
        CSV2POD_RUNTIMECLASS="$POD_RUNTIMECLASS" \
        CSV2POD_IMAGE_LOCAL="$POD_IMAGE_LOCAL" \
        CSV2POD_IMAGE_UPSTREAM="$POD_IMAGE_UPSTREAM" \
        CSV2POD_REGISTRY="$POD_REGISTRY" \
        CSV2POD_INITDATA="$POD_INITDATA" \
        CSV2POD_PULL_TIMEOUT="$POD_PULL_TIMEOUT" \
        CSV2POD_DRY_RUN="$dry_run" \
        CSV2POD_SKIP_PUSH="$skip_push" \
        CSV2POD_SELF="$(basename "$0")" \
        bash -s <<'POD_UP'
set -euo pipefail

NS="$CSV2POD_NAMESPACE"
POD="$CSV2POD_POD_NAME"
PW="$(printf '%s' "$CSV2POD_PASSWORD_B64" | base64 -d)"
TPL=/tmp/csv2-pod.template.yaml
RENDERED=/tmp/csv2-pod.rendered.yaml

say() { echo "  $*"; }
bad() { echo "  FAIL $*" >&2; exit 1; }

echo "==> pod preflight"
command -v kubectl >/dev/null || bad "no kubectl on the host"
command -v docker  >/dev/null || bad "no docker on the host"
kubectl version >/dev/null 2>&1 || bad "cannot reach the cluster (kubectl version)"

kubectl get runtimeclass "$CSV2POD_RUNTIMECLASS" >/dev/null 2>&1 \
    || bad "runtimeclass $CSV2POD_RUNTIMECLASS does not exist"

# Refuse rather than replace. This pod is shared, there is one DCU on the host, and
# deleting somebody else's work to make room is not this script's call to make.
if kubectl -n "$NS" get pod "$POD" >/dev/null 2>&1; then
    bad "'$NS/$POD' already exists; delete it first with: $CSV2POD_SELF pod-down"
fi

# Written like the registry probe below and for the same reason: `... | grep -q` lets
# grep exit on the match, SIGPIPEs the writer, and pipefail then reports the port as
# free. Collecting the list first leaves nothing upstream to kill.
used_ports="$(kubectl get svc -A -o jsonpath='{range .items[*]}{.spec.ports[*].nodePort}{"\n"}{end}' 2>/dev/null || true)"
if grep -qx "$CSV2POD_NODE_PORT" <<< "$used_ports"; then
    bad "nodePort $CSV2POD_NODE_PORT is already taken; it is fixed in the template"
fi

# Informational only: the DCU is advertised by a device plugin, and a stale
# advertisement outlives the card. One card, so a second DCU pod just stays Pending.
dcu_used="$(kubectl get pods -A -o json 2>/dev/null \
            | grep -o '"hygon\.cn/k100_ai":[^,}]*' | sort -u || true)"
if [ -n "$dcu_used" ]; then
    say "WARN something already claims hygon.cn/k100_ai:"
    printf '         %s\n' $dcu_used
    say "WARN one DCU on this host - unless it frees up, this pod stays Pending"
fi

echo "==> image"
# The guest pulls the image itself, so having it in the host's docker is not enough.
# It has to be in a registry the guest can reach.
registry_has_image() {
    local out
    # Not `curl ... | grep -q`: grep -q exits on the first match, curl takes SIGPIPE,
    # and pipefail reads the pipeline as a failure.
    out="$(curl -sk --max-time 10 "https://$CSV2POD_REGISTRY/v2/vllm/tags/list" 2>/dev/null || true)"
    grep -q 'ubuntu-dtk' <<< "$out"
}

if registry_has_image; then
    say "the registry already has vllm:ubuntu-dtk"
elif [ "$CSV2POD_DRY_RUN" = 1 ]; then
    say "WARN dry run: the registry has no vllm:ubuntu-dtk, and a dry run pushes nothing"
elif [ "$CSV2POD_SKIP_PUSH" = 1 ]; then
    bad "the registry has no vllm:ubuntu-dtk and --skip-push was given"
else
    docker image inspect "$CSV2POD_IMAGE_UPSTREAM" >/dev/null 2>&1 \
        || bad "the host has no $CSV2POD_IMAGE_UPSTREAM, and this script does not download.
         save it where there is network, then: gunzip -c vllm-dtk.tar.gz | docker load"
    say "tagging and pushing; 25.6GB, this takes minutes"
    docker tag  "$CSV2POD_IMAGE_UPSTREAM" "$CSV2POD_IMAGE_LOCAL"
    docker push "$CSV2POD_IMAGE_LOCAL" \
        || bad "the push failed; check the registry and whether its CA is trusted at
         /etc/docker/certs.d/$CSV2POD_REGISTRY/ca.crt"
    registry_has_image \
        || bad "the push reported success, but the registry still does not list the tag"
fi

echo "==> render"
[ -f "$CSV2POD_INITDATA" ] || bad "initdata $CSV2POD_INITDATA is missing"
# The guest verifies TLS when it pulls. The host trusting the registry's self-signed
# certificate does not make the guest trust it; this blob is what does, by way of the
# CoCo initdata.
INITDATA_B64="$(gzip -c "$CSV2POD_INITDATA" | base64 -w0)"
[ -n "$INITDATA_B64" ] || bad "could not build the initdata blob"
say "initdata ${#INITDATA_B64} chars (2008 expected)"

printf '%s' "$CSV2POD_TEMPLATE_B64" | base64 -d > "$TPL"
[ -s "$TPL" ] || bad "the template came through empty"

sed -e "s|__INITDATA_B64__|${INITDATA_B64}|g" \
    -e "s|__SSH_PASSWORD__|${PW}|g" \
    "$TPL" > "$RENDERED"

# The class has to include digits. `__[A-Z_]` misses __INITDATA_B64__, which is the
# one most likely to survive unreplaced, since its value is computed here rather than
# written anywhere.
leftover="$(grep -oE '__[A-Z0-9_]+__' "$RENDERED" | sort -u | tr '\n' ' ' || true)"
[ -z "$leftover" ] || bad "unreplaced placeholders after rendering: $leftover"
say "rendered $RENDERED"

if [ "$CSV2POD_DRY_RUN" = 1 ]; then
    say "dry run: nothing applied"
    say "apply by hand with: kubectl -n $NS apply -f $RENDERED"
    exit 0
fi

echo "==> apply"
kubectl -n "$NS" apply -f "$RENDERED" || bad "apply failed"

echo "==> waiting for Ready, up to ${CSV2POD_PULL_TIMEOUT}s"
say "the guest pulls its own 25.6GB image, so this is slow"
start=$(date +%s)
last_msg=""
while :; do
    now=$(date +%s); elapsed=$((now - start))

    phase=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || echo "?")
    reason=$(kubectl -n "$NS" get pod "$POD" \
                -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)
    msg="${phase}${reason:+ / $reason}"

    # On change only: this can run for forty minutes.
    if [ "$msg" != "$last_msg" ]; then
        printf '  [%4ds] %s\n' "$elapsed" "$msg"
        last_msg="$msg"
    fi

    case "$phase" in
        Running)
            ready=$(kubectl -n "$NS" get pod "$POD" \
                        -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null || echo false)
            if [ "$ready" = "true" ]; then
                printf '  [%4ds] Running / Ready\n' "$elapsed"
                break
            fi
            ;;
        Failed|Succeeded)
            echo "  FAIL the pod went to $phase:" >&2
            kubectl -n "$NS" logs "$POD" --tail=80 >&2 || true
            exit 1
            ;;
    esac

    if [ "$elapsed" -ge "$CSV2POD_PULL_TIMEOUT" ]; then
        echo "  FAIL still $msg after ${CSV2POD_PULL_TIMEOUT}s:" >&2
        kubectl -n "$NS" describe pod "$POD" 2>&1 | tail -40 >&2 || true
        exit 1
    fi
    sleep 10
done

echo "==> verify"
# The kata runtime builds its own QEMU, and that is where the card shows up as passed
# through. `ls /dev/dri/` inside is the other half of the check.
qemu_cmds="$(pgrep -af qemu-system-x86_64 2>/dev/null || true)"
if grep -q 'vfio-pci,host=0000:c3:00.0' <<< "$qemu_cmds"; then
    say "ok    DCU passed through: $(grep -o 'vfio-pci,host=[^ ]*' <<< "$qemu_cmds" | sort -u | tr '\n' ' ')"
else
    say "WARN no vfio-pci device on any QEMU command line; look inside with ls /dev/dri/"
fi

if timeout 5 bash -c "echo > /dev/tcp/127.0.0.1/$CSV2POD_NODE_PORT" 2>/dev/null; then
    say "ok    nodePort $CSV2POD_NODE_PORT answers"
else
    say "WARN nodePort $CSV2POD_NODE_PORT does not answer. Check that sshd started:"
    say "        kubectl -n $NS logs $POD --tail=30"
    say "      or use the fallback that needs no CNI:"
    say "        kubectl -n $NS port-forward pod/$POD 2222:22"
fi

echo
echo "================= pod ready =================="
echo "  pod      : $NS/$POD"
echo "  nodePort : $CSV2POD_NODE_PORT"
echo "  password : $PW"
echo
echo "  ssh -o StrictHostKeyChecking=no -p $CSV2POD_NODE_PORT root@${CSV2POD_REGISTRY%%:*}"
echo
echo "  inside, the DCU should answer:  hy-smi ; ls /dev/dri/ ; rocminfo"
echo "  if they are missing, load the DTK environment first: bash -lc 'hy-smi'"
echo
echo "  delete it with: $CSV2POD_SELF pod-down"
echo "=============================================="
POD_UP
}

cmd_pod_status() {
    pod_facts || return 1

    echo "==> DCU test pod $POD_NAMESPACE/$POD_NAME"
    host env \
        CSV2POD_NAMESPACE="$POD_NAMESPACE" \
        CSV2POD_POD_NAME="$POD_NAME" \
        CSV2POD_NODE_PORT="$POD_NODE_PORT" \
        CSV2POD_SERVICE="$POD_SERVICE" \
        bash -s <<'POD_STATUS'
set -uo pipefail
NS="$CSV2POD_NAMESPACE"; POD="$CSV2POD_POD_NAME"

command -v kubectl >/dev/null || { echo "  no kubectl on the host" >&2; exit 1; }

if kubectl -n "$NS" get pod "$POD" >/dev/null 2>&1; then
    phase=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || echo "?")
    ready=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null || echo "?")
    reason=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)
    node=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)
    printf '  pod      : %s/%s  %s  ready=%s%s\n' "$NS" "$POD" "$phase" "$ready" "${reason:+  ($reason)}"
    printf '  node     : %s\n' "${node:-?}"
else
    echo "  pod      : $NS/$POD does not exist"
fi

if kubectl -n "$NS" get svc "$CSV2POD_SERVICE" >/dev/null 2>&1; then
    echo "  service  : $CSV2POD_SERVICE  (nodePort $CSV2POD_NODE_PORT)"
else
    echo "  service  : $CSV2POD_SERVICE does not exist"
fi

# A stale advertisement outlives the card, so this is what the node believes, not
# necessarily what is true.
dcu_lines="$(kubectl describe nodes 2>/dev/null | grep -E 'hygon\.cn/k100_ai' | sed -n '1,4p' || true)"
if [ -n "$dcu_lines" ]; then
    echo "  DCU      : the node advertises"
    printf '%s\n' "$dcu_lines" | sed 's/^/             /'
else
    echo "  DCU      : the node advertises no hygon.cn/k100_ai at all"
fi

qemu_cmds="$(pgrep -af qemu-system-x86_64 2>/dev/null || true)"
if grep -q 'vfio-pci,host=0000:c3:00.0' <<< "$qemu_cmds"; then
    echo "  vfio     : the DCU is passed through to a running VM"
else
    echo "  vfio     : no QEMU has the DCU"
fi

qemu_now="$(pgrep -cf qemu-system-x86_64 2>/dev/null || true)"
echo "  QEMU     : ${qemu_now:-0} process(es) on the host"
POD_STATUS
}

cmd_pod_down() {
    local keep_service=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --keep-service) keep_service=1; shift ;;
            *) echo "pod-down: unknown argument $1" >&2; return 1 ;;
        esac
    done

    pod_facts || return 1

    echo "==> deleting DCU test pod $POD_NAMESPACE/$POD_NAME"
    host env \
        CSV2POD_NAMESPACE="$POD_NAMESPACE" \
        CSV2POD_POD_NAME="$POD_NAME" \
        CSV2POD_NODE_PORT="$POD_NODE_PORT" \
        CSV2POD_SERVICE="$POD_SERVICE" \
        CSV2POD_SELF="$(basename "$0")" \
        CSV2POD_KEEP_SERVICE="$keep_service" \
        bash -s <<'POD_DOWN'
set -uo pipefail
# Deliberately no -e: a cleanup that stops at the first failure leaves a half-deleted
# pod. The exit status is set explicitly at the end instead.

NS="$CSV2POD_NAMESPACE"; POD="$CSV2POD_POD_NAME"; SVC="$CSV2POD_SERVICE"
NODE_PORT="$CSV2POD_NODE_PORT"
failed=0

command -v kubectl >/dev/null || { echo "  FAIL no kubectl on the host" >&2; exit 1; }

echo "==> recording the sandbox id"
# Worth doing while the pod is still there. Afterwards this id is the only way to tell
# which kata shim and QEMU processes this pod left behind - the choice is between
# knowing, and guessing at other people's processes.
find_sandbox_id() {
    # NS and POD have to be exported. Written as `NS=x crictl ... | python3 ...` the
    # assignment would apply to crictl alone, python would raise KeyError on
    # os.environ, and the function would swallow it into an empty answer.
    export NS POD
    crictl pods -o json 2>/dev/null | python3 -c '
import json, sys, os
ns, name = os.environ["NS"], os.environ["POD"]
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for it in data.get("items", []):
    lbl = it.get("labels") or {}
    if (lbl.get("io.kubernetes.pod.namespace") == ns
            and lbl.get("io.kubernetes.pod.name") == name):
        # The id is on the item itself. metadata holds only attempt/name/namespace/uid,
        # so reading it from there returns empty without raising.
        print(it.get("id", ""))
        break
'
}

SANDBOX_ID="$(find_sandbox_id)"
if [ -n "$SANDBOX_ID" ]; then
    echo "  sandbox ${SANDBOX_ID:0:16}..."
else
    echo "  no sandbox id - the pod never started, or is already gone"
fi

echo "==> deleting the pod"
if kubectl -n "$NS" get pod "$POD" >/dev/null 2>&1; then
    kubectl -n "$NS" delete pod "$POD" --timeout=90s >/dev/null 2>&1
    if kubectl -n "$NS" get pod "$POD" >/dev/null 2>&1; then
        echo "  graceful delete did not finish (usual for kata), forcing"
        kubectl -n "$NS" delete pod "$POD" --grace-period=0 --force >/dev/null 2>&1
        sleep 3
        if kubectl -n "$NS" get pod "$POD" >/dev/null 2>&1; then
            echo "  FAIL the pod object is still there; look at it by hand:" >&2
            echo "         kubectl -n $NS get pod $POD -o yaml | tail -30" >&2
            failed=1
        else
            echo "  forced delete done"
        fi
    else
        echo "  deleted"
    fi
else
    echo "  $NS/$POD does not exist, nothing to delete"
fi

echo "==> deleting the Service"
if [ "$CSV2POD_KEEP_SERVICE" = 1 ]; then
    echo "  --keep-service: keeping $SVC"
elif kubectl -n "$NS" get svc "$SVC" >/dev/null 2>&1; then
    if kubectl -n "$NS" delete svc "$SVC" >/dev/null 2>&1; then
        echo "  deleted $SVC, nodePort released"
    else
        echo "  WARN could not delete $SVC"
    fi
else
    echo "  $SVC does not exist, nothing to delete"
fi

echo "==> leftover processes"
# This host's recurring trouble: a kata shim that will not exit leaves its QEMU
# behind, and the next pod then trips over "object with key already exists".
#
# Only processes tied to this pod's sandbox are killed. With no sandbox id nothing is
# killed at all - the alternative is guessing, and guessing means somebody else's pod.
killed=0
if [ -n "$SANDBOX_ID" ]; then
    short_id="${SANDBOX_ID:0:16}"
    for pid in $(pgrep -f containerd-shim-kata 2>/dev/null || true); do
        # The 2>/dev/null has to wrap the whole group, not tr: a pid pgrep just named
        # can be gone by now, and that message comes from the shell's own input
        # redirection, before tr is ever started.
        cmd=$( { tr '\0' ' ' < "/proc/$pid/cmdline"; } 2>/dev/null )
        case "$cmd" in
            *"$SANDBOX_ID"*|*"$short_id"*)
                echo "  killing leftover kata shim pid=$pid"
                kill -9 "$pid" 2>/dev/null && killed=$((killed + 1))
                ;;
        esac
    done
    for pid in $(pgrep -f qemu-system-x86_64 2>/dev/null || true); do
        # The 2>/dev/null has to wrap the whole group, not tr: a pid pgrep just named
        # can be gone by now, and that message comes from the shell's own input
        # redirection, before tr is ever started.
        cmd=$( { tr '\0' ' ' < "/proc/$pid/cmdline"; } 2>/dev/null )
        case "$cmd" in
            *"$SANDBOX_ID"*|*"$short_id"*)
                echo "  killing leftover QEMU pid=$pid"
                kill -9 "$pid" 2>/dev/null && killed=$((killed + 1))
                ;;
        esac
    done
else
    echo "  no sandbox id, so nothing is killed here (that would risk other pods)"
fi

# Report orphans that belong to nobody, without touching them. The comparison has to
# use the full 64-character id: `crictl pods -q` returns 12 characters, which never
# matches what is carved out of a command line, and every live process would then be
# reported as an orphan.
live_sandboxes="$(crictl pods -o json 2>/dev/null | python3 -c '
import json, sys
try:
    for it in json.load(sys.stdin).get("items", []):
        print(it.get("id", ""))
except Exception:
    pass
' 2>/dev/null || true)"
orphans=0
for pid in $(pgrep -f containerd-shim-kata 2>/dev/null || true); do
    # Grouped so the 2>/dev/null also covers a pid that vanished between pgrep and
    # this read: that message comes from the shell's own input redirection.
    cmd=$( { tr '\0' ' ' < "/proc/$pid/cmdline"; } 2>/dev/null )
    # `sed -n 1p` rather than `head -1`: head would exit early and SIGPIPE grep.
    sb="$(printf '%s' "$cmd" | grep -oE '[0-9a-f]{64}' | sed -n '1p' || true)"
    [ -n "$sb" ] || continue
    if ! grep -q "$sb" <<< "$live_sandboxes"; then
        orphans=$((orphans + 1))
        [ "$orphans" = 1 ] && echo "  WARN other orphaned kata shims, not this pod's - left alone:"
        printf '         pid=%s sandbox=%s...\n' "$pid" "${sb:0:16}"
    fi
done

if [ "$killed" = 0 ] && [ "$orphans" = 0 ]; then
    echo "  none"
fi

echo "==> verify"
if kubectl -n "$NS" get pod "$POD" >/dev/null 2>&1; then
    echo "  FAIL the pod is still there"
    failed=1
else
    echo "  ok    the pod is gone"
fi

# A bare pod has no controller, so nothing brings it back - unless somebody left one.
controllers="$(kubectl -n "$NS" get deploy,rs,sts,ds,job,cronjob -o name 2>/dev/null | grep -i "$POD" || true)"
if [ -n "$controllers" ]; then
    echo "  WARN something could recreate it:"
    printf '         %s\n' $controllers
else
    echo "  ok    nothing owns it, so it will not come back on its own"
fi

if [ "$CSV2POD_KEEP_SERVICE" = 0 ]; then
    used_ports="$(kubectl get svc -A -o jsonpath='{range .items[*]}{.spec.ports[*].nodePort}{"\n"}{end}' 2>/dev/null || true)"
    if grep -qx "$NODE_PORT" <<< "$used_ports"; then
        echo "  WARN nodePort $NODE_PORT is still taken (by some other Service)"
    fi
fi

qemu_now="$(pgrep -cf qemu-system-x86_64 2>/dev/null || true)"
echo "  QEMU  : ${qemu_now:-0} process(es) left on the host"

echo
echo "================= pod deleted ================="
echo "  $NS/$POD is gone, and nothing will rebuild it."
echo "  recreate it with: $CSV2POD_SELF pod-up"
echo "==============================================="

exit "$failed"
POD_DOWN
}

# ------------------------------- entrypoint ----------------------------------

case "${1:-}" in
    deps)     shift; cmd_deps "$@" ;;
    up)       shift; cmd_up "$@" ;;
    status)   shift; cmd_status "$@" ;;
    verify)   shift; cmd_verify "$@" ;;
    measure)  shift; cmd_measure "$@" ;;
    ssh)      shift; cmd_ssh "$@" ;;
    down)     shift; cmd_down "$@" ;;
    dcu-base) shift; cmd_dcu_base "$@" ;;
    pod-up)   shift; cmd_pod_up "$@" ;;
    pod-status) shift; cmd_pod_status "$@" ;;
    pod-down) shift; cmd_pod_down "$@" ;;
    *)
        # Print the header comment block: leading comment lines only, stopping at
        # the first line of code.
        awk 'NR > 1 { if ($0 ~ /^#/) { sub(/^# ?/, ""); print; next } exit }' "$0"
        exit 1
        ;;
esac
