#!/bin/sh
#
# build.sh - build one wlanpatch-<arch>.ko from src/<arch>/.
#
# The wlan_fils.c stub supplies struct module, .modinfo and the vermagic, so no
# vendor module is needed.  wlanpatch.c (with the shared src/common engine)
# supplies the patcher.  patch-module.py finalises the linked object.
#
# Usage: ARCH=mips|arm ./scripts/build.sh    (output: out/<arch>/wlanpatch-<arch>.ko)
#
# Requires the matching cross toolchain and python3:
#   mips -> mips-linux-gnu-gcc / -ld        (apt: gcc-mips-linux-gnu)
#   arm  -> arm-linux-gnueabi-gcc / -ld     (apt: gcc-arm-linux-gnueabi)
set -eu

ARCH=${ARCH:?set ARCH=mips|arm}
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SRC=$BASE/src/$ARCH
OUT=${OUT:-$BASE/out/$ARCH}

[ -d "$SRC" ] || { echo "error: no src/$ARCH" >&2; exit 1; }

case "$ARCH" in
    mips)
        CC=${CC:-mips-linux-gnu-gcc}
        LD=${LD:-mips-linux-gnu-ld}
        CFLAGS="-O2 -mabi=32 -march=mips32r2 -EB -mno-abicalls -fno-pic -G0 \
            -fno-stack-protector -ffreestanding \
            -fno-unwind-tables -fno-asynchronous-unwind-tables"
        ;;
    arm)
        CC=${CC:-arm-linux-gnueabi-gcc}
        LD=${LD:-arm-linux-gnueabi-ld}
        CFLAGS="-O2 -march=armv7-a -marm -mfloat-abi=soft -fno-pic \
            -fno-stack-protector -ffreestanding \
            -fno-unwind-tables -fno-asynchronous-unwind-tables"
        ;;
    ppc)
        CC=${CC:-powerpc-linux-gnu-gcc}
        LD=${LD:-powerpc-linux-gnu-ld}
        CFLAGS="-O2 -mcpu=powerpc -msoft-float -msdata=none -G0 -fno-pic \
            -fno-stack-protector -ffreestanding \
            -fno-unwind-tables -fno-asynchronous-unwind-tables"
        ;;
    *)
        echo "error: unknown ARCH=$ARCH (expected mips|arm|ppc)" >&2
        exit 1
        ;;
esac

command -v "$CC" >/dev/null 2>&1 || { echo "error: $CC not found" >&2; exit 1; }
command -v "$LD" >/dev/null 2>&1 || { echo "error: $LD not found" >&2; exit 1; }

# Deterministic output for reproducible rebuilds.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
export LC_ALL=C TZ=UTC

WORK=$(mktemp -d "${TMPDIR:-/tmp}/wlanpatch-$ARCH.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# wlanpatch.c defines init_module/cleanup_module; rename them to the symbols the
# stub references so the module owns its entry points.
$CC -c $CFLAGS \
    -Dinit_module=wlanpatch_init -Dcleanup_module=wlanpatch_cleanup \
    -o "$WORK/wlanpatch.o" "$SRC/wlanpatch.c"
$CC -c $CFLAGS -o "$WORK/wlan_fils.o" "$SRC/wlan_fils.c"
$LD -r -o "$WORK/wlanpatch-$ARCH.ko" "$WORK/wlan_fils.o" "$WORK/wlanpatch.o"
python3 "$BASE/scripts/patch-module.py" "$WORK/wlanpatch-$ARCH.ko"

mkdir -p "$OUT"
cp -f "$WORK/wlanpatch-$ARCH.ko" "$OUT/wlanpatch-$ARCH.ko"

sha=$(sha256sum "$OUT/wlanpatch-$ARCH.ko" | awk '{print $1}')
echo "built $OUT/wlanpatch-$ARCH.ko ($sha)"
