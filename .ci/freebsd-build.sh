#!/bin/bash
# Builds and tests Open vSwitch inside a FreeBSD QEMU VM.
#
# Steps mirror the original Cirrus CI configuration:
#   configure -> ./boot.sh && ./configure CC=<compiler> ...
#   build     -> gmake -j8
#   check     -> gmake -j8 check TESTSUITEFLAGS=-j8 RECHECK=yes
#
# All CI dependencies are pre-installed in the cached image by nuageinit
# during the prepare phase (see freebsd-prepare-image.sh).
#
# Required environment variables:
#   FREEBSD_VER   - FreeBSD version string, e.g. "14.4" or "15.0"
#   COMPILER      - compiler to use: "gcc" or "clang"
#
# The cached image freebsd-<FREEBSD_VER>.qcow2 must exist in the current
# directory before this script is called (restored from actions/cache by the
# workflow).

set -o errexit
set -o xtrace

FREEBSD_VER="${FREEBSD_VER:?Must set FREEBSD_VER (e.g. 14.4)}"
COMPILER="${COMPILER:?Must set COMPILER (gcc or clang)}"

BASE_IMG="freebsd-${FREEBSD_VER}.qcow2"
RUN_IMG="freebsd-run.qcow2"

if [ ! -f "${BASE_IMG}" ]; then
    echo "ERROR: ${BASE_IMG} not found." \
         "Ensure the cache was restored before calling this script." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Install host-side tools
# ---------------------------------------------------------------------------
sudo apt-get update -qq
sudo apt-get install -y \
    qemu-system-x86 qemu-utils \
    genisoimage \
    rsync openssh-client \
    ovmf

# ---------------------------------------------------------------------------
# 2. Source VM utilities
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=freebsd-vm.sh
. "${SCRIPT_DIR}/freebsd-vm.sh"

# ---------------------------------------------------------------------------
# 3. Generate an ephemeral SSH key for this CI run
# ---------------------------------------------------------------------------
KEY_DIR="$(mktemp -d)"
SSH_KEY="${KEY_DIR}/id_ed25519"
ssh-keygen -t ed25519 -f "${SSH_KEY}" -N "" -q
export FREEBSD_SSH_KEY="${SSH_KEY}"

# ---------------------------------------------------------------------------
# 4. Create a COW overlay on top of the cached base image
# ---------------------------------------------------------------------------
# COW overlay keeps the cached base image unmodified.
echo "==> Creating COW overlay image ..."
qemu-img create -f qcow2 -F qcow2 -b "$(realpath "${BASE_IMG}")" "${RUN_IMG}"

# ---------------------------------------------------------------------------
# 5. Create a seed ISO with a fresh instance-id
# ---------------------------------------------------------------------------
SEED_INSTANCE_ID="freebsd-build-${FREEBSD_VER}-${COMPILER}-$(date +%s%N)"
freebsd_create_seed \
    "${SSH_KEY}.pub" \
    "${SEED_INSTANCE_ID}" \
    /tmp/freebsd-seed-build \
    /tmp/freebsd-seed-build.iso

# ---------------------------------------------------------------------------
# 6. Boot the VM
# ---------------------------------------------------------------------------
echo "==> Booting FreeBSD ${FREEBSD_VER} (compiler: ${COMPILER}) ..."

BUILD_OVMF_VARS="/tmp/freebsd-ovmf-vars-build.fd"
cp "${FREEBSD_OVMF_VARS}" "${BUILD_OVMF_VARS}"

freebsd_start_vm \
    "${RUN_IMG}" /tmp/freebsd-seed-build.iso 4096 4 "${BUILD_OVMF_VARS}"

cleanup() {
    # Retrieve logs before stopping the VM (|| true handles boot failures).
    echo "==> Retrieving logs ..."
    mkdir -p tests
    freebsd_rsync_from /root/ovs/config.log        ./      2>/dev/null || true
    freebsd_rsync_from /root/ovs/tests/testsuite.log tests/ 2>/dev/null || true
    freebsd_rsync_from /root/ovs/tests/testsuite.dir tests/ 2>/dev/null || true
    freebsd_stop_vm
    rm -rf "${KEY_DIR}" "${RUN_IMG}" "${BUILD_OVMF_VARS}" \
           /tmp/freebsd-seed-build /tmp/freebsd-seed-build.iso
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 7. Wait for SSH, then wait for firstboot to complete
# ---------------------------------------------------------------------------
# Wait for SSH, then ensure all firstboot rc scripts (including the sshd
# restart runcmd) have completed before proceeding.
# SSH wait: 20 x 10s = 200s.  Firstboot wait: 30 x 5s = 150s.
freebsd_wait_ssh 20 10
freebsd_wait_firstboot_complete 30 5

# ---------------------------------------------------------------------------
# 8. Sync source tree into the VM
# ---------------------------------------------------------------------------
echo "==> Syncing source tree to VM ..."
freebsd_ssh "mkdir -p /root/ovs"
freebsd_rsync_to "$(pwd)/" /root/ovs/

# ---------------------------------------------------------------------------
# 9. Configure
# ---------------------------------------------------------------------------
echo "==> Configuring (CC=${COMPILER}) ..."
freebsd_ssh "cd /root/ovs && \
    ./boot.sh && \
    ./configure CC=${COMPILER} CFLAGS='-g -O2 -Wall' MAKE=gmake \
        --enable-Werror \
    || { cat config.log; exit 1; }"

# ---------------------------------------------------------------------------
# 10. Build
# ---------------------------------------------------------------------------
echo "==> Building ..."
freebsd_ssh "cd /root/ovs && gmake -j8"

# ---------------------------------------------------------------------------
# 11. Test
# ---------------------------------------------------------------------------
echo "==> Running test suite ..."
freebsd_ssh "cd /root/ovs && \
    gmake -j8 check TESTSUITEFLAGS=-j8 RECHECK=yes \
    || { cat ./tests/testsuite.log; exit 1; }"

echo "==> FreeBSD ${FREEBSD_VER} ${COMPILER} build complete."
