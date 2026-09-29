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
#     $HOST_OVMF               OVMF built with confidential-guest support. Must match
#                              the firmware the base image was installed against.
#     /dev/sev                 PSP device. Memory encryption is impossible without it.
#     /etc/qemu/bridge.conf    must allow the bridge, or QEMU refuses to attach it.
#     <bridge>                 LAN uplink; also where the guest's DHCP lease comes from.
#
#   guest side - already inside the base image, nothing to stage
#     /lib/modules/$(uname -r)/kernel/drivers/virt/coco/csv-guest/csv-guest.ko.xz
#                              provides /dev/csv-guest, the attestation interface.
#                              Not loaded by default; `up` and `verify` modprobe it.
#
#   verification only - optional, needed by `verify` alone
#     $SMOKE_BIN               TAA attestation smoke test, copied into the guest.
#     $CERT_DIR/hrk.cert, $CERT_DIR/hsk_cek.cert
#                              Hygon root and endorsement certs, for chain checking.
#
# Usage:
#   ./tools/csv2-vm/csv2-vm.sh deps     list the required files and whether they exist
#   ./tools/csv2-vm/csv2-vm.sh up       create (if needed) and boot the VM
#   ./tools/csv2-vm/csv2-vm.sh status   read-only status + CSV2 encryption check
#   ./tools/csv2-vm/csv2-vm.sh verify   run the TAA CSV attestation smoke test in the guest
#   ./tools/csv2-vm/csv2-vm.sh ssh      open a shell in the guest
#   ./tools/csv2-vm/csv2-vm.sh down     stop the VM and clean runtime files
#   ./tools/csv2-vm/csv2-vm.sh down --purge-disk
#                                       also delete the overlay disk (DESTRUCTIVE:
#                                       discards all guest state; the read-only base
#                                       image is left alone so it can be recreated)
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
#   CSV2_VNC_DISPLAY host VNC display               (default 9)
#   CSV2_VM_VCPUS / CSV2_VM_MEM_MB                  (default 8 / 16384)
#   CSV2_DISK       overlay path                    (default <images>/<name>-overlay.qcow2)
#
# Every later command must be given the same overrides, or it will address the
# default instance instead. The guest is addressed by the LAN DHCP server, so an
# instance without CSV2_VM_IP is discovered after boot: first from the bridge
# neighbour table, then by reading `hostname -I` over the serial console.
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
HOST_DISK="${CSV2_DISK:-$HOST_DISK_DIR/$VM_NAME-overlay.qcow2}"
# Read-only devkit base image shipped by Hygon; only ever used as a backing file.
HOST_BASE_DISK="${CSV2_BASE_DISK:-/opt/hygon/csv/vm.qcow2}"
# OVMF build with confidential-guest support; must match the firmware the guest
# was installed against.
HOST_OVMF=/opt/hygon/csv/OVMF_CODE.fd
HOST_QEMU=/usr/bin/qemu-system-x86_64
HOST_BRIDGE=br0

HOST_PIDFILE="/run/$VM_NAME.pid"
HOST_SERIAL="/run/$VM_NAME.serial"
HOST_CONSOLE_LOG="/var/log/$VM_NAME-console.log"
HOST_QMP_PORT="${CSV2_QMP_PORT:-2223}"
HOST_VNC_DISPLAY="${CSV2_VNC_DISPLAY:-9}"

# policy=0x5 decodes as NODBG(0x1) | ES(0x4). The ES bit is what makes this CSV2
# rather than CSV1: guest register state is encrypted, not just memory.
# cbitpos/reduced-phys-bits are Hygon-specific (AMD parts use 51/1).
VM_POLICY=0x5
VM_CBITPOS=47
VM_REDUCED_PHYS_BITS=5

# Attestation smoke test, run inside the guest (host paths).
SMOKE_BIN="${CSV2_SMOKE_BIN:-/root/taa/csv-go-smoke}"
CERT_DIR="${CSV2_CERT_DIR:-/root/taa}"

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
    local out
    out=$(host "{ sleep 3; printf '\n'; sleep 2; printf 'root\n'; sleep 4; printf '${CSV2_GUEST_PASS}\n'; sleep 5; printf 'hostname -I\n'; sleep 3; } | timeout 45 socat - UNIX-CONNECT:${HOST_SERIAL} 2>&1" 2>/dev/null \
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
        if [ -f "\$p" ]; then status="ok (\$(du -h "\$p" 2>/dev/null | cut -f1))"; else status="ok"; fi
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

echo
echo "guest side - already inside the base image, nothing to stage:"
printf "  %-56s  %-36s  %s\n" "csv-guest.ko.xz" "provides /dev/csv-guest" "in base image"

echo
echo "verification only - needed by 'verify', not by 'up':"
row "$SMOKE_BIN" "attestation smoke test" optional
row "$CERT_DIR/hrk.cert" "Hygon root key (HRK) cert" optional
row "$CERT_DIR/hsk_cek.cert" "Hygon endorsement (HSK/CEK) cert" optional

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

exit \$fail
EOF
}

cmd_up() {
    if vm_running; then
        echo "$VM_NAME already running (pid $(vm_pid))"
        return 0
    fi

    preflight

    echo "==> overlay disk"
    host_script <<EOF
set -e
if [ -f "$HOST_DISK" ]; then
    echo "  reusing existing overlay (guest state preserved): $HOST_DISK"
else
    # Fresh overlay on the read-only base image.
    qemu-img create -f qcow2 -F qcow2 -b "$HOST_BASE_DISK" "$HOST_DISK"
    echo "  created overlay: $HOST_DISK"
fi
EOF

    echo "==> launching $VM_NAME (policy=$VM_POLICY -> CSV2, ${VM_VCPUS} vCPU, ${VM_MEM_MB}MB)"
    host_script <<EOF
set -e
$HOST_QEMU -name $VM_NAME \\
    --enable-kvm -cpu host -smp $VM_VCPUS -m $VM_MEM_MB \\
    -hda "$HOST_DISK" \\
    -drive if=pflash,format=raw,unit=0,file=$HOST_OVMF,readonly=on \\
    -qmp tcp:127.0.0.1:$HOST_QMP_PORT,server,nowait \\
    -vnc 127.0.0.1:$HOST_VNC_DISPLAY \\
    -object sev-guest,id=sev0,policy=$VM_POLICY,cbitpos=$VM_CBITPOS,reduced-phys-bits=$VM_REDUCED_PHYS_BITS \\
    -machine memory-encryption=sev0 \\
    -netdev bridge,br=$HOST_BRIDGE,id=net0 \\
    -device virtio-net-pci,netdev=net0,mac=$VM_MAC,romfile= \\
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

    echo "==> done"
    echo "  name  $VM_NAME"
    echo "  guest $VM_IP (mac $VM_MAC)"
    echo "  stop  $(basename "$0") down   [with CSV2_VM_NAME=$VM_NAME]"
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
    kind = {5: 'CSV2', 69: 'CSV3'}.get(sev.get('policy'), 'policy=%s' % sev.get('policy'))
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
sshpass -e scp -o StrictHostKeyChecking=accept-new "$SMOKE_BIN" root@$VM_IP:/root/ >/dev/null
# Chain verification needs the Hygon HRK/HSK-CEK certs alongside the binary.
if [ -f "$CERT_DIR/hrk.cert" ] && [ -f "$CERT_DIR/hsk_cek.cert" ]; then
    sshpass -e scp -o StrictHostKeyChecking=accept-new \\
        "$CERT_DIR/hrk.cert" "$CERT_DIR/hsk_cek.cert" root@$VM_IP:/root/ >/dev/null
    echo "certs: copied from $CERT_DIR"
else
    echo "certs: not found under $CERT_DIR, report signature only" >&2
fi
sshpass -e ssh -o StrictHostKeyChecking=accept-new root@$VM_IP \\
    '/root/$(basename $SMOKE_BIN) -verify-chain -out /root/smoke-chain.json; echo "EXIT=\$?"; cat /root/smoke-chain.json'
EOF
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
}

# ------------------------------- entrypoint ----------------------------------

case "${1:-}" in
    deps)   shift; cmd_deps "$@" ;;
    up)     shift; cmd_up "$@" ;;
    status) shift; cmd_status "$@" ;;
    verify) shift; cmd_verify "$@" ;;
    ssh)    shift; cmd_ssh "$@" ;;
    down)   shift; cmd_down "$@" ;;
    *)
        # Print the header comment block: leading comment lines only, stopping at
        # the first line of code.
        awk 'NR > 1 { if ($0 ~ /^#/) { sub(/^# ?/, ""); print; next } exit }' "$0"
        exit 1
        ;;
esac
