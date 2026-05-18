#!/bin/bash
# Prepares a FreeBSD QEMU VM image with all CI dependencies pre-installed.
#
# Usage: freebsd-prepare-image.sh <freebsd_version>
#   freebsd_version  e.g. "14.4" or "15.0"
#
# Downloads the FreeBSD BASIC-CLOUDINIT qcow2 image, verifies its SHA256,
# grows the disk, runs the two-boot nuageinit sequence (SSH key injection,
# package install, PermitRootLogin), restores /firstboot for build job boots,
# and compresses the result for caching.  Boot sequence details: freebsd-vm.sh.
#
# Output file: freebsd-<version>.qcow2  (in the current directory)

set -o errexit
set -o xtrace

# Capture the exact command that triggers errexit so the EXIT trap can print
# a clear "FAILED: <cmd>" line.  Without this the failure is buried in
# xtrace noise.
_FAILED_CMD=""
trap '_FAILED_CMD="${BASH_COMMAND}"' ERR

FREEBSD_VER="${1:?Usage: $0 <version>  (e.g. 14.4)}"

RELEASE="${FREEBSD_VER}-RELEASE"
ARCH="amd64"
BASE_URL="https://download.freebsd.org/releases/VM-IMAGES"
BASE_URL="${BASE_URL}/${RELEASE}/${ARCH}/Latest"

IMG_NAME="FreeBSD-${RELEASE}-${ARCH}-BASIC-CLOUDINIT-ufs.qcow2"
IMG_XZ="${IMG_NAME}.xz"
OUT_IMG="freebsd-${FREEBSD_VER}.qcow2"

# ---------------------------------------------------------------------------
# 1. Install host-side tools
# ---------------------------------------------------------------------------
sudo apt-get update -qq
sudo apt-get install -y \
    qemu-system-x86 qemu-utils \
    genisoimage \
    wget xz-utils \
    ovmf

# ---------------------------------------------------------------------------
# 2. Download and verify the FreeBSD image
# ---------------------------------------------------------------------------
echo "==> Fetching CHECKSUM.SHA256 ..."
wget -q "${BASE_URL}/CHECKSUM.SHA256" -O freebsd-checksum.txt

echo "==> Downloading ${IMG_XZ} ..."
wget -q "${BASE_URL}/${IMG_XZ}" -O "${IMG_XZ}"

echo "==> Verifying image integrity ..."
expected_sha=$(grep "(${IMG_XZ})" freebsd-checksum.txt | awk '{print $NF}')
actual_sha=$(sha256sum "${IMG_XZ}" | awk '{print $1}')
if [ "${expected_sha}" != "${actual_sha}" ]; then
    echo "ERROR: SHA256 mismatch for ${IMG_XZ}" >&2
    echo "  expected: ${expected_sha}" >&2
    echo "  actual:   ${actual_sha}" >&2
    exit 1
fi

echo "==> Extracting image ..."
xz --decompress --keep "${IMG_XZ}"
mv "${IMG_NAME}" "${OUT_IMG}"
rm -f "${IMG_XZ}"

# ---------------------------------------------------------------------------
# 3. Grow the disk to make room for packages
# ---------------------------------------------------------------------------
echo "==> Resizing disk to +8G ..."
qemu-img resize "${OUT_IMG}" +8G

# ---------------------------------------------------------------------------
# 4. Generate an ephemeral SSH key for this preparation run
# ---------------------------------------------------------------------------
PREP_KEY_DIR="$(mktemp -d)"
PREP_KEY="${PREP_KEY_DIR}/id_ed25519"
ssh-keygen -t ed25519 -f "${PREP_KEY}" -N "" -q

# ---------------------------------------------------------------------------
# 5. Source VM utilities
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=freebsd-vm.sh
. "${SCRIPT_DIR}/freebsd-vm.sh"
export FREEBSD_SSH_KEY="${PREP_KEY}"

# ---------------------------------------------------------------------------
# 6. Boot the VM with a seed ISO
# ---------------------------------------------------------------------------
SEED_INSTANCE_ID="freebsd-prepare-${FREEBSD_VER}-$(date +%s)"
freebsd_create_seed \
    "${PREP_KEY}.pub" \
    "${SEED_INSTANCE_ID}" \
    /tmp/freebsd-seed-prepare \
    /tmp/freebsd-seed-prepare.iso

echo "==> Booting FreeBSD ${FREEBSD_VER} for image preparation ..."

PREP_OVMF_VARS="/tmp/freebsd-ovmf-vars-prepare.fd"
cp "${FREEBSD_OVMF_VARS}" "${PREP_OVMF_VARS}"

freebsd_start_vm \
    "${OUT_IMG}" /tmp/freebsd-seed-prepare.iso 4096 4 "${PREP_OVMF_VARS}"

_prep_cleanup() {
    local rc=$?
    if [ "${rc}" -ne 0 ]; then
        echo "### PREPARE FAILED (rc=${rc}): ${_FAILED_CMD} ###" >&2
    fi
    freebsd_stop_vm
    rm -rf "${PREP_KEY_DIR}" "${PREP_OVMF_VARS}" \
           /tmp/freebsd-seed-prepare /tmp/freebsd-seed-prepare.iso
}
trap _prep_cleanup EXIT

# ---------------------------------------------------------------------------
# 7. Wait for SSH, then wait for firstboot to complete
# ---------------------------------------------------------------------------
# Covers two boots: Boot 1 (freebsd-update + reboot) + Boot 2 (packages +
# runcmds).  Must finish before "touch /firstboot" (step 8).
# SSH wait: 90 x 10s = 900s.  Firstboot wait: 12 x 10s = 120s.
freebsd_wait_ssh 90 10
freebsd_wait_firstboot_complete 12 10

# ---------------------------------------------------------------------------
# 8. Restore /firstboot so build job boots re-run nuageinit
# ---------------------------------------------------------------------------
# Restore /firstboot so nuageinit runs on build job boots to inject
# per-job SSH keys.
echo "==> Restoring /firstboot for build job boots ..."
freebsd_ssh "touch /firstboot"

echo "==> Shutting down FreeBSD ${FREEBSD_VER} ..."
freebsd_stop_vm
_prep_cleanup() {
    rm -rf "${PREP_KEY_DIR}" "${PREP_OVMF_VARS}" \
           /tmp/freebsd-seed-prepare /tmp/freebsd-seed-prepare.iso
}
trap _prep_cleanup EXIT

# ---------------------------------------------------------------------------
# 9. Compress the prepared image for caching
# ---------------------------------------------------------------------------
echo "==> Compressing prepared image ..."
COMPRESSED="${OUT_IMG}.compressed"
qemu-img convert -c -O qcow2 "${OUT_IMG}" "${COMPRESSED}"
mv "${COMPRESSED}" "${OUT_IMG}"

FINAL_SIZE=$(du -sh "${OUT_IMG}" | cut -f1)
echo "==> Image preparation complete."
echo "    Output : ${OUT_IMG}"
echo "    Size   : ${FINAL_SIZE}"
