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
# Usage:
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
# Example:
#   CSV2_HOST_PASS='...' ./tools/csv2-vm/csv2-vm.sh up
#
set -euo pipefail

# ------------------------------- configuration -------------------------------

CSV2_HOST="${CSV2_HOST:-root@172.16.10.178}"
CSV2_HOST_PASS="${CSV2_HOST_PASS:-}"
CSV2_GUEST_PASS="${CSV2_GUEST_PASS:-root}"

# Guest identity. The MAC is fixed so the LAN bridge hands out the same lease,
# which keeps the guest reachable at a stable address across reboots.
VM_NAME=csv2-8c16g
VM_IP=172.16.10.171
VM_MAC=52:54:00:12:34:56
VM_VCPUS=8
VM_MEM_MB=16384

HOST_DISK_DIR=/data/var/lib/libvirt/images
HOST_DISK="$HOST_DISK_DIR/$VM_NAME-overlay.qcow2"
# Read-only devkit base image shipped by Hygon; only ever used as a backing file.
HOST_BASE_DISK=/opt/hygon/csv/vm.qcow2
# OVMF build with confidential-guest support; must match the firmware the guest
# was installed against.
HOST_OVMF=/opt/hygon/csv/OVMF_CODE.fd
HOST_QEMU=/usr/bin/qemu-system-x86_64
HOST_BRIDGE=br0

HOST_PIDFILE="/run/$VM_NAME.pid"
HOST_SERIAL="/run/$VM_NAME.serial"
HOST_CONSOLE_LOG="/var/log/$VM_NAME-console.log"
HOST_QMP_PORT=2223

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

vm_running() {
    local pid
    pid=$(vm_pid)
    [ -n "$pid" ] || return 1
    host "[ -d /proc/$pid ]" 2>/dev/null
}

# ------------------------------- commands ------------------------------------

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

# Do not take an address that something else already answers on.
if ping -c 1 -W 2 $VM_IP >/dev/null 2>&1; then
    echo "  FAIL $VM_IP already responds (address collision)"; fail=1
else
    echo "  ok   $VM_IP is free"
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
    -vnc 127.0.0.1:9 \\
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

    echo "==> waiting for guest ssh"
    local i
    for i in $(seq 1 36); do
        if host "timeout 3 bash -c 'echo > /dev/tcp/$VM_IP/22'" 2>/dev/null; then
            echo "  guest reachable at $VM_IP (after ~$((i * 10))s)"
            break
        fi
        sleep 10
    done
    if ! host "timeout 3 bash -c 'echo > /dev/tcp/$VM_IP/22'" 2>/dev/null; then
        echo "  guest ssh did not come up; check $HOST_CONSOLE_LOG" >&2
        return 1
    fi

    # /dev/csv-guest is provided by the csv-guest module and is NOT loaded by
    # default. Without it TAA's attestation path finds no device and degrades to
    # simulation mode, so load it as part of bring-up.
    echo "==> loading csv-guest module in guest"
    guest_script <<'GUEST'
set -e
if [ -c /dev/csv-guest ]; then
    echo "  /dev/csv-guest already present"
else
    modprobe csv-guest
    echo "  modprobe csv-guest done"
fi
ls -la /dev/csv-guest
GUEST

    echo "==> done"
}

cmd_status() {
    if ! vm_running; then
        echo "$VM_NAME is not running"
        return 1
    fi

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

if ping -c 1 -W 2 $VM_IP >/dev/null 2>&1; then
    echo "network     $VM_IP reachable (mac $VM_MAC)"
else
    echo "network     $VM_IP unreachable"
fi
echo "console     $HOST_CONSOLE_LOG"
EOF
}

cmd_verify() {
    vm_running || { echo "$VM_NAME is not running" >&2; return 1; }

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
    up)     shift; cmd_up "$@" ;;
    status) shift; cmd_status "$@" ;;
    verify) shift; cmd_verify "$@" ;;
    ssh)    shift; cmd_ssh "$@" ;;
    down)   shift; cmd_down "$@" ;;
    *)
        sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
        exit 1
        ;;
esac
