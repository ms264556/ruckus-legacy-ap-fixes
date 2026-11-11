#!/bin/sh
#
# run.sh - tests for rmc-radiusd's guest-pass roles (guestd, portal) on a Linux build host.
#
# Usage: tests/guest/run.sh                     build the roles for the host (cc) and test them
#        tests/guest/run.sh qemu-arm out/radiusd/rmc-radiusd-arm
#                                               test a built rmc-radiusd (any command that runs it)
# Needs python3 and a C compiler; the stand-in idm, authd, controller port and hostapd are Python (test_guest.py).
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$HERE/../../src/radiusd/guest

if [ $# -eq 0 ]; then
    BUILD=$(mktemp -d)
    trap 'rm -rf "$BUILD"' EXIT
    ${CC:-cc} -std=gnu99 -Os -Wall -Wextra -Werror -I"$SRC" -o "$BUILD/rmc-guest-host" \
        "$HERE/main.c" "$HERE/sha256.c" "$SRC/rmc-guest.c" "$SRC/rmc-guestd.c" "$SRC/rmc-portal.c"
    set -- "$BUILD/rmc-guest-host"
fi
python3 "$HERE/test_guest.py" "$@"
