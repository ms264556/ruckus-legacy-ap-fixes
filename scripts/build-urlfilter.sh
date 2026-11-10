#!/bin/sh
#
# build-urlfilter.sh - build a static rmc-urlfilter-<arch>: the stand-in for uf_agent on SmartZone 3.6 images that
# ship avpd without it (src/urlfilter/rmc-urlfilter.c), and rmc-dpi-shim-<arch>.so, which lets avpd run its DPI engine
# on 3.6 APs with 200 000 kB of RAM or less (src/urlfilter/rmc-dpi-shim.c). Same compiler as build-iperf3.sh: Zig's
# bundled clang and musl, pinned by version and SHA-256; the agent statically linked, the shim a libc-free shared
# object (it is preloaded into a uClibc process); soft-float on MIPS.
#
# Usage: ARCH=arm|mips|ppc ./scripts/build-urlfilter.sh
#   output: out/urlfilter/rmc-urlfilter-<arch>, out/urlfilter/rmc-dpi-shim-<arch>.so
#        ZIG=/path/to/zig to use an already unpacked Zig 0.14.1;
#        DOWNLOADS=<dir> to keep the downloaded tarball (default: a temp dir).
set -eu

ARCH=${ARCH:?set ARCH=arm|mips|ppc}
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${OUT:-$BASE/out/urlfilter}

ZIG_VERSION=0.14.1
case "$(uname -m)" in
    x86_64)  ZIG_HOST=x86_64-linux;  ZIG_SHA256=24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c ;;
    aarch64) ZIG_HOST=aarch64-linux; ZIG_SHA256=f7a654acc967864f7a050ddacfaa778c7504a0eca8d2b678839c21eea47c992b ;;
    *) echo "error: no pinned Zig for build host $(uname -m)" >&2; exit 1 ;;
esac
ZIG_URL=https://ziglang.org/download/$ZIG_VERSION/zig-$ZIG_HOST-$ZIG_VERSION.tar.xz

case "$ARCH" in
    arm)  TARGET=arm-linux-musleabi;     MCPU=generic+v7a ;;
    mips) TARGET=mips-linux-musleabi;    MCPU=mips32r2+soft_float ;;
    ppc)  TARGET=powerpc-linux-musleabi; MCPU=440-isel ;;
    *) echo "error: unknown ARCH=$ARCH (expected arm|mips|ppc)" >&2; exit 1 ;;
esac

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
export LC_ALL=C TZ=UTC

WORK=$(mktemp -d "${TMPDIR:-/tmp}/urlfilter-$ARCH.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
DL=${DOWNLOADS:-$WORK/dl}
mkdir -p "$DL" "$OUT"

if [ -z "${ZIG:-}" ]; then
    f=zig-$ZIG_HOST-$ZIG_VERSION.tar.xz
    [ -f "$DL/$f" ] || curl -sSfL -o "$DL/$f" "$ZIG_URL"
    echo "$ZIG_SHA256  $DL/$f" | sha256sum -c - >/dev/null || { echo "error: $f does not match its pinned SHA-256" >&2; exit 1; }
    tar -C "$WORK" -xJf "$DL/$f"
    ZIG=$WORK/zig-$ZIG_HOST-$ZIG_VERSION/zig
fi
export ZIG_GLOBAL_CACHE_DIR=$WORK/zig-cache ZIG_LOCAL_CACHE_DIR=$WORK/zig-cache

"$ZIG" cc -target "$TARGET" -mcpu="$MCPU" -std=c11 -D_DEFAULT_SOURCE -Os -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -static -Wl,--gc-sections -s \
    -o "$OUT/rmc-urlfilter-$ARCH" "$BASE/src/urlfilter/rmc-urlfilter.c" "$BASE/src/urlfilter/rmc-filter.c" -lpthread
"$ZIG" cc -target "$TARGET" -mcpu="$MCPU" -std=c11 -Os -Wall -Wextra -Werror \
    -shared -fPIC -nostdlib -rtlib=none -Wl,-z,max-page-size=4096 -s -o "$OUT/rmc-dpi-shim-$ARCH.so" "$BASE/src/urlfilter/rmc-dpi-shim.c"
file "$OUT/rmc-urlfilter-$ARCH" "$OUT/rmc-dpi-shim-$ARCH.so" 2>/dev/null || true
ls -l "$OUT/rmc-urlfilter-$ARCH" "$OUT/rmc-dpi-shim-$ARCH.so"
