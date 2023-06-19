#!/bin/bash

set -ex

PROGRAM=`basename $0`
TARGET=check-${PROGRAM}

# The autopkgtests are run in throwaway environments, let's be good citizens
# regardless, and attempt to clean up any environment modifications.
function cleanup {
    rc=$?

    set +e

    # Dump the log to console on error
    if [ $rc -ne 0 ]; then
        case "${PROGRAM}" in
            kernel)
                # For historical reasons the log for the system kernel
                # datapath testsuite has a deviant name.
                logname="kmod"
            ;;
            *)
                logname="${PROGRAM}"
            ;;
        esac
        if [ -f _debian/tests/system-${logname}-testsuite.log ]; then
            cat _debian/tests/system-${logname}-testsuite.log
        fi
    fi

    # The DPDK test requires post-test cleanup steps.
    if [ "$PROGRAM" = "dpdk" ]; then
        mv /etc/dpdk/dpdk.conf.bak /etc/dpdk/dpdk.conf
        systemctl restart dpdk

        if dirs +1 > /dev/null 2>&1; then
            popd
            umount ${BIND_MOUNT_DIR}
            rmdir ${BIND_MOUNT_DIR}
        fi
    fi

    exit $rc
}
trap cleanup EXIT

# The DPDK test requires preparing steps.
if [ "$PROGRAM" = "dpdk" ]; then
    ARCH=$(dpkg --print-architecture)
    echo "Check required features on arch: ${ARCH}"
    case "${ARCH}" in
        amd64)
            # For amd64 the OVS DPDK support works with ssse3
            # https://github.com/openvswitch/ovs/blob/8045c0f8de5192355ca438ed7eef77457c3c1625/acinclude.m4#LL441C52-L441C52
            if ! grep -q '^flags.*sse3' /proc/cpuinfo; then
                echo "Missing ssse3 on ${ARCH} - not supported, SKIP test"
                exit 77
            fi
            ;;
        arm64)
            if ! grep -q '^Features.*crc32' /proc/cpuinfo; then
                echo "Missing crc32 on ${ARCH} - not supported, SKIP test"
                exit 77
            fi
            ;;
    esac
    echo "no known missing feature on ${ARCH}, continue test"

    # Allocate hugepages, use 2M pages when possible because of higher
    # probability of successful allocation at runtime and smaller test
    # footprint in CI virtual machines.
    #
    # If the tests are to be run on real physical hardware, you may need
    # to adjust these variables depending on CPU architecture and topology.
    numa_node=$(lscpu | awk '/NUMA node\(s\)/{print$3}')
    if [ -z "$numa_node" -o "$numa_node" -eq 0 ]; then
        numa_node=1
    fi
    DPDK_NR_1G_PAGES=${DPDK_NR_1G_PAGES:-0}
    DPDK_NR_2M_PAGES=${DPDK_NR_2M_PAGES:-$((${numa_node} * (2667 + 512) / 2))}

    printf "Determine hugepage allocation for %s NUMA Node(s) on arch: %s" \
        ${numa_node} ${ARCH}
    echo "DPDK_NR_2M_PAGES=${DPDK_NR_2M_PAGES}"
    echo "DPDK_NR_1G_PAGES=${DPDK_NR_1G_PAGES}"

    mv /etc/dpdk/dpdk.conf /etc/dpdk/dpdk.conf.bak
    cat << EOF > /etc/dpdk/dpdk.conf
NR_1G_PAGES=${DPDK_NR_1G_PAGES}
NR_2M_PAGES=${DPDK_NR_2M_PAGES}
DROPCACHE_BEFORE_HP_ALLOC=1
EOF
    systemctl restart dpdk
    realhp_2m=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
    realhp_1g=$(cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages)
    if [ "$realhp_2m" != "$DPDK_NR_2M_PAGES" -o \
         "$realhp_1g" != "$DPDK_NR_1G_PAGES" ]; then
        echo "Unable to allocate huge pages required for the test, SKIP test"
        exit 77
    fi

    # Long log messages from DPDK library overflow and is written as multiple
    # lines.  This does not play well with the OVS testsuite assertions.  Even
    # a tmp directory in /tmp will make the paths too long.
    #
    # Realpaths from build will be embedded in testsuite artifacts, so we do
    # this before the build, and use a bind mount to avoid copying data around
    # (using a symlink would not be sufficient).
    #
    # Ensure we use a short path for running the testsuite (LP:# 2019069).
    BIND_MOUNT_DIR=$(mktemp -d /XXX)
    mount --bind . ${BIND_MOUNT_DIR}
    pushd ${BIND_MOUNT_DIR}
fi

# A built source tree is required in order to make use of the system level
# testsuites.
#
# We build it here instead of using the `build-needed` Restriction field,
# because we need to pass in additional environment variables in order to
# avoid running the build time checks yet another time (they would have just
# run as part of the package under test build process anyway).
export DEB_BUILD_OPTIONS="nocheck $DEB_BUILD_OPTIONS"
debian/rules build

# Ensure none of the Open vSwitch daemons are running.
systemctl stop \
    openvswitch-ipsec \
    openvswitch-testcontroller \
    ovs-vswitchd \
    ovsdb-server

# Optionally build list of tests to run, an empty list means run all tests.
TEST_LIST=""
if [ -f debian/tests/${PROGRAM}-skip-tests.txt ]; then
    TEST_LIST=$(cat debian/tests/${PROGRAM}-skip-tests.txt | \
                debian/tests/testlist.py - tests/system-${PROGRAM}-testsuite)
fi

# Run the testsuite.
#
# By not having paths from build directory in AUTOTEST_PATH, apart from
# `tests`, will ensure binaries are executed from system PATH, i.e. from the
# binary package under test, and not the built source tree.
make \
    -C _debian \
    ${TARGET} \
    AUTOTEST_PATH=tests \
    TESTSUITEFLAGS="-j1 ${TEST_LIST}" \
    RECHECK=yes
