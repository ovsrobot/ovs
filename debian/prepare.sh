#!/bin/sh

set -e

srcdir=$(dirname "$0")/..

# Generate debian/control from control.in.
# With --dpdk, uncomment DPDK_NETDEV lines; without, strip them.
if [ "$1" = "--dpdk" ]; then
    sed -e 's/^\# DPDK_NETDEV //' \
        < "$srcdir/debian/control.in" > "$srcdir/debian/control"
else
    grep -v '^\# DPDK_NETDEV' \
        "$srcdir/debian/control.in" > "$srcdir/debian/control"
fi

# Generate debian/copyright from copyright.in and AUTHORS.rst.
{ sed -n -e '/%AUTHORS%/q' -e p < "$srcdir/debian/copyright.in"
  tail -n +28 "$srcdir/AUTHORS.rst" | sed '1,/^$/d' |
    sed -n -e '/^$/q' -e 's/^/  /p'
  sed -e '1,/%AUTHORS%/d' "$srcdir/debian/copyright.in"
} > "$srcdir/debian/copyright"
