#!/bin/bash
# FreeBSD QEMU VM management utilities.
#
# Source this file from other scripts; do NOT execute it directly.
#
# Required environment variables (set before sourcing or calling functions):
#   FREEBSD_SSH_KEY   - path to the private SSH key for VM access
#
# Optional environment variables:
#   FREEBSD_SSH_PORT  - host port forwarded to VM's SSH (default: 2222)
#   FREEBSD_VM_PIDFILE - path for the QEMU pid file
#                        (default: /tmp/freebsd-vm.pid)

FREEBSD_SSH_PORT="${FREEBSD_SSH_PORT:-2222}"
FREEBSD_VM_PIDFILE="${FREEBSD_VM_PIDFILE:-/tmp/freebsd-vm.pid}"

# OVMF firmware paths (Ubuntu 24.04, package: ovmf).
FREEBSD_OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
FREEBSD_OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"

# SSH options for VM communication.  Host key checking disabled (ephemeral VM).
_freebsd_ssh_opts() {
    echo "-p ${FREEBSD_SSH_PORT}"
    echo "-i ${FREEBSD_SSH_KEY}"
    echo "-o StrictHostKeyChecking=no"
    echo "-o UserKnownHostsFile=/dev/null"
    echo "-o ConnectTimeout=5"
    echo "-o BatchMode=yes"
    echo "-o ServerAliveInterval=15"
    echo "-o ServerAliveCountMax=4"
    echo "-o LogLevel=ERROR"
}

# freebsd_kvm_opts
# Emits KVM flags if /dev/kvm is available, falls back to software emulation.
freebsd_kvm_opts() {
    if [ -e /dev/kvm ] && [ -r /dev/kvm ]; then
        echo "-enable-kvm -cpu host"
    else
        echo "WARNING: /dev/kvm not available; falling back to software" \
             "emulation.  Build times will be significantly longer." >&2
        echo "-cpu qemu64"
    fi
}

# freebsd_start_vm <image.qcow2> [seed.iso] [mem_mb] [cpus] [ovmf_vars.fd]
# Boots a FreeBSD VM in the background.
#   image.qcow2  - disk image (may be a COW overlay)
#   seed.iso     - optional cloud-init NoCloud seed ISO
#   mem_mb       - RAM in megabytes (default: 4096)
#   cpus         - vCPU count (default: 4)
#   ovmf_vars.fd - path to a *writable* copy of FREEBSD_OVMF_VARS for UEFI
#                  boot.  FreeBSD BASIC-CLOUDINIT images use GPT/EFI and
#                  require UEFI firmware.  When absent the VM falls back to
#                  SeaBIOS (legacy BIOS).
freebsd_start_vm() {
    local img_file="${1:?freebsd_start_vm: image file required}"
    local seed_iso="${2:-}"
    local mem="${3:-4096}"
    local cpus="${4:-4}"
    local ovmf_vars="${5:-}"

    local seed_args=""
    if [ -n "${seed_iso}" ]; then
        # Attach seed ISO via AHCI controller — AHCI is probed during PCI
        # bus scan, early enough for nuageinit.  FreeBSD creates
        # /dev/iso9660/cidata from the volume ID.
        seed_args="-device ahci,id=ahci0"
        seed_args="${seed_args} -drive"
        seed_args="${seed_args} if=none,id=seed_drive"
        seed_args="${seed_args},file=${seed_iso}"
        seed_args="${seed_args},format=raw,media=cdrom,readonly=on"
        seed_args="${seed_args} -device ide-cd,bus=ahci0.0,drive=seed_drive"
    fi

    # UEFI firmware (OVMF).  FreeBSD BASIC-CLOUDINIT images require GPT/EFI
    # boot.  The vars file must be a writable per-VM copy.
    local ovmf_args=""
    if [ -n "${ovmf_vars}" ]; then
        ovmf_args="-drive"
        ovmf_args="${ovmf_args} if=pflash,format=raw"
        ovmf_args="${ovmf_args},readonly=on,file=${FREEBSD_OVMF_CODE}"
        ovmf_args="${ovmf_args} -drive if=pflash,format=raw,file=${ovmf_vars}"
    fi

    # Build the full QEMU command into an array.
    # shellcheck disable=SC2046
    local qemu_cmd
    qemu_cmd=(
        qemu-system-x86_64
        $(freebsd_kvm_opts)
        -m "${mem}"
        -smp "${cpus}"
        -nographic
        -netdev "user,id=net0,hostfwd=tcp::${FREEBSD_SSH_PORT}-:22"
        -device virtio-net-pci,netdev=net0
        -drive "file=${img_file},if=virtio,format=qcow2,cache=unsafe"
        -device virtio-rng-pci
        -pidfile "${FREEBSD_VM_PIDFILE}"
    )

    if [ -n "${seed_args}" ]; then
        # shellcheck disable=SC2206
        qemu_cmd+=( ${seed_args} )
    fi
    if [ -n "${ovmf_args}" ]; then
        # shellcheck disable=SC2206
        qemu_cmd+=( ${ovmf_args} )
    fi

    "${qemu_cmd[@]}" > /tmp/freebsd-vm.log 2>&1 &

    echo "FreeBSD VM launched (PID $!); log: /tmp/freebsd-vm.log"
}

# freebsd_wait_ssh [max_attempts] [delay_seconds]
# Polls SSH port until the VM responds or we exhaust attempts.
# Returns 0 on success, 1 on timeout.
freebsd_wait_ssh() {
    local max_attempts="${1:-20}"
    local delay="${2:-10}"

    echo "Waiting for SSH on localhost:${FREEBSD_SSH_PORT} ..."
    local i
    for i in $(seq 1 "${max_attempts}"); do
        # shellcheck disable=SC2046
        if ssh $(tr '\n' ' ' < <(_freebsd_ssh_opts)) \
               root@localhost true 2>/dev/null; then
            echo "SSH ready after attempt ${i}."
            return 0
        fi

        echo "  attempt ${i}/${max_attempts}, retrying in ${delay}s ..."

        if [ "${i}" != "${max_attempts}" ]; then
            sleep "${delay}"
        fi
    done

    echo "ERROR: SSH did not become available after" \
         "$((max_attempts * delay))s." >&2
    return 1
}

# freebsd_wait_firstboot_complete [max_attempts] [delay_seconds]
# Polls until /firstboot is absent, which means rc.d/firstboot has finished all
# firstboot-keyed rc scripts — including nuageinit_user_data_script and its
# "sshd onerestart" runcmd.  Call after freebsd_wait_ssh; without this, SSH
# commands can be killed mid-flight by that sshd restart.
freebsd_wait_firstboot_complete() {
    local max_attempts="${1:-30}"
    local delay="${2:-5}"

    echo "Waiting for firstboot to complete (/firstboot to be removed) ..."
    local i
    for i in $(seq 1 "${max_attempts}"); do
        if freebsd_ssh "test ! -f /firstboot" 2>/dev/null; then
            echo "Firstboot sequence complete (attempt ${i})."
            return 0
        fi
        echo "  /firstboot still present (attempt ${i}/${max_attempts})," \
             "waiting ${delay}s ..."
        sleep "${delay}"
    done

    echo "ERROR: /firstboot still present after" \
         "$((max_attempts * delay))s." >&2
    return 1
}

# freebsd_ssh <command ...>
# Runs a command inside the VM as root.
freebsd_ssh() {
    # shellcheck disable=SC2046
    ssh $(tr '\n' ' ' < <(_freebsd_ssh_opts)) root@localhost "$@"
}

# freebsd_rsync_to <local_src> <vm_dst>
# Rsyncs from the host into the VM.
freebsd_rsync_to() {
    local src="${1:?freebsd_rsync_to: source required}"
    local dst="${2:?freebsd_rsync_to: destination required}"
    # shellcheck disable=SC2046
    rsync -az --delete \
        -e "ssh $(tr '\n' ' ' < <(_freebsd_ssh_opts))" \
        "${src}" "root@localhost:${dst}"
}

# freebsd_rsync_from <vm_src> <local_dst>
# Rsyncs from the VM back to the host.
freebsd_rsync_from() {
    local src="${1:?freebsd_rsync_from: source required}"
    local dst="${2:?freebsd_rsync_from: destination required}"
    # shellcheck disable=SC2046
    rsync -az \
        -e "ssh $(tr '\n' ' ' < <(_freebsd_ssh_opts))" \
        "root@localhost:${src}" "${dst}"
}

# freebsd_stop_vm
# Gracefully shuts down the VM; kills QEMU if it does not exit in time.
freebsd_stop_vm() {
    if [ ! -f "${FREEBSD_VM_PIDFILE}" ]; then
        return 0
    fi

    local pid
    pid=$(cat "${FREEBSD_VM_PIDFILE}" 2>/dev/null) || return 0

    echo "Shutting down FreeBSD VM (PID ${pid}) ..."
    freebsd_ssh "shutdown -p now" 2>/dev/null || true

    local i
    for i in $(seq 1 30); do
        kill -0 "${pid}" 2>/dev/null || {
            echo "VM exited cleanly."
            rm -f "${FREEBSD_VM_PIDFILE}"
            return 0
        }
        sleep 2
    done

    echo "VM did not stop in time; killing QEMU."
    kill "${pid}" 2>/dev/null || true
    rm -f "${FREEBSD_VM_PIDFILE}"
}

# freebsd_create_seed <pubkey_file> <instance_id> <work_dir> <output_iso>
#                     [label]
# Creates a NoCloud seed ISO that injects <pubkey_file> into root
# authorized_keys
# and installs CI dependencies via nuageinit.
#
# label (optional, default: cidata):
#   ISO 9660 volume ID passed to genisoimage/mkisofs.  nuageinit on FreeBSD
#   14.x+ BASIC-CLOUDINIT images recognises the "cidata" NoCloud label.
freebsd_create_seed() {
    local pub_key_file="${1:?freebsd_create_seed: public key file required}"
    local instance_id="${2:?freebsd_create_seed: instance-id required}"
    local work_dir="${3:-/tmp/freebsd-seed}"
    local out_iso="${4:-/tmp/freebsd-seed.iso}"
    local label="${5:-cidata}"

    local pub_key
    pub_key=$(cat "${pub_key_file}")

    mkdir -p "${work_dir}"

    cat > "${work_dir}/meta-data" <<EOF
instance-id: ${instance_id}
local-hostname: freebsd-ci
EOF

    # py311-* names match FreeBSD 14/15 default Python 3.11.
    cat > "${work_dir}/user-data" <<EOF
#cloud-config
users:
  - name: root
    ssh_authorized_keys:
      - ${pub_key}
package_update: true
packages:
  - automake
  - libtool
  - gmake
  - gcc
  - openssl
  - python3
  - rsync
  - py311-sphinx
  - py311-netaddr
  - py311-pyparsing
runcmd:
  - printf '\nPermitRootLogin yes\n' >> /etc/ssh/sshd_config
  - grep -q kern.coredump /etc/sysctl.conf || echo 'kern.coredump=0' >> /etc/sysctl.conf
  - sysctl -w kern.coredump=0 || true
  - service sshd onerestart || true
EOF

    if command -v genisoimage >/dev/null 2>&1; then
        genisoimage -output "${out_iso}" \
            -volid "${label}" -rational-rock -joliet \
            "${work_dir}/user-data" "${work_dir}/meta-data" 2>/dev/null
    else
        mkisofs -output "${out_iso}" \
            -volid "${label}" -rational-rock -joliet \
            "${work_dir}/user-data" "${work_dir}/meta-data"
    fi

    echo "Seed ISO created: ${out_iso} (label: ${label})"
}
