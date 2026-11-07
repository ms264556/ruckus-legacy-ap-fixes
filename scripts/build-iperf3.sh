#!/bin/sh
#
# build-iperf3.sh - build a static iperf3-<arch> for the APs' speed tests.
#
# SmartZone 7.x firmware ships iperf3; 2.6 to 6.1 do not. These binaries let a
# controller run AP-to-AP speed tests on the older firmware too: one file per
# CPU family, statically linked against musl (glibc's static binaries refuse
# the 2.6.32 kernels of the MIPS and PowerPC APs), soft-float, no OpenSSL
# (iperf3's optional login is not needed).
#
#   arm   32-bit ARMv7, kernel 3.14 (3.6 to 6.1 ARM APs)
#   mips  MIPS32r2 big-endian, kernel 2.6.32 (2.6 ZoneFlex)
#   ppc   32-bit PowerPC big-endian, kernel 2.6.32 (R700 family, 2.6 to 5.1)
#
# The compiler is Zig's bundled clang and musl, pinned by version and SHA-256,
# and iperf3 is the upstream release tarball, pinned by SHA-256.
#
# Usage: ARCH=arm|mips|ppc ./scripts/build-iperf3.sh
#   output: out/iperf3/iperf3-<arch>, plus the licences the binary carries:
#   out/iperf3/LICENSE.iperf3 (BSD-3-Clause) and out/iperf3/COPYRIGHT.musl (MIT)
#        ZIG=/path/to/zig to use an already unpacked Zig 0.14.1;
#        DOWNLOADS=<dir> to keep the downloaded tarballs (default: a temp dir).
set -eu

ARCH=${ARCH:?set ARCH=arm|mips|ppc}
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${OUT:-$BASE/out/iperf3}

IPERF_VERSION=3.21
IPERF_SHA256=656e4405ebd620121de7ceca3eaf43a88f79ea1b857d041a6a0b1314801acdd8
IPERF_URL=https://github.com/esnet/iperf/releases/download/$IPERF_VERSION/iperf-$IPERF_VERSION.tar.gz
ZIG_VERSION=0.14.1
case "$(uname -m)" in
    x86_64)  ZIG_HOST=x86_64-linux;  ZIG_SHA256=24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c ;;
    aarch64) ZIG_HOST=aarch64-linux; ZIG_SHA256=f7a654acc967864f7a050ddacfaa778c7504a0eca8d2b678839c21eea47c992b ;;
    *) echo "error: no pinned Zig for build host $(uname -m)" >&2; exit 1 ;;
esac
ZIG_URL=https://ziglang.org/download/$ZIG_VERSION/zig-$ZIG_HOST-$ZIG_VERSION.tar.xz

case "$ARCH" in
    arm)  TARGET=arm-linux-musleabi;     MCPU=generic+v7a;          HOST=arm-linux-musleabi ;;
    mips) TARGET=mips-linux-musleabi;    MCPU=mips32r2+soft_float;  HOST=mips-linux-musl ;;
    ppc)  TARGET=powerpc-linux-musleabi; MCPU=440-isel;             HOST=powerpc-linux-musl ;;
    *) echo "error: unknown ARCH=$ARCH (expected arm|mips|ppc)" >&2; exit 1 ;;
esac

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
export LC_ALL=C TZ=UTC

WORK=$(mktemp -d "${TMPDIR:-/tmp}/iperf3-$ARCH.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
DL=${DOWNLOADS:-$WORK/dl}
mkdir -p "$DL" "$OUT"

# fetch <url> <sha256> <file>: download once, always verify.
fetch() {
    [ -f "$DL/$3" ] || curl -sSfL -o "$DL/$3" "$1"
    echo "$2  $DL/$3" | sha256sum -c - >/dev/null || { echo "error: $3 does not match its pinned SHA-256" >&2; rm -f "$DL/$3"; exit 1; }
}

if [ -z "${ZIG:-}" ]; then
    fetch "$ZIG_URL" "$ZIG_SHA256" "zig-$ZIG_HOST-$ZIG_VERSION.tar.xz"
    tar -C "$WORK" -xJf "$DL/zig-$ZIG_HOST-$ZIG_VERSION.tar.xz"
    ZIG=$WORK/zig-$ZIG_HOST-$ZIG_VERSION/zig
fi
fetch "$IPERF_URL" "$IPERF_SHA256" "iperf-$IPERF_VERSION.tar.gz"
tar -C "$WORK" -xzf "$DL/iperf-$IPERF_VERSION.tar.gz"

# configure wants single-word tools.
for tool in cc ar ranlib; do
    case $tool in
        cc) cmd="cc -target $TARGET -mcpu=$MCPU" ;;
        *)  cmd=$tool ;;
    esac
    printf '#!/bin/sh\nexec "%s" %s "$@"\n' "$ZIG" "$cmd" > "$WORK/zig-$tool"
    chmod +x "$WORK/zig-$tool"
done
export ZIG_GLOBAL_CACHE_DIR=$WORK/zig-cache ZIG_LOCAL_CACHE_DIR=$WORK/zig-cache

cd "$WORK/iperf-$IPERF_VERSION"
./configure --host="$HOST" --build="$(uname -m)-linux-gnu" \
    --enable-static-bin --disable-shared --without-openssl --without-sctp \
    CC="$WORK/zig-cc" AR="$WORK/zig-ar" RANLIB="$WORK/zig-ranlib" \
    CFLAGS="-Os -ffunction-sections -fdata-sections" LDFLAGS="-static -Wl,--gc-sections -s" >"$WORK/configure.log" 2>&1 \
    || { tail -40 "$WORK/configure.log" >&2; exit 1; }
make -j"$(nproc)" >"$WORK/make.log" 2>&1 || { tail -40 "$WORK/make.log" >&2; exit 1; }

cp -f src/iperf3 "$OUT/iperf3-$ARCH"
cp -f LICENSE "$OUT/LICENSE.iperf3"
cp -f "$(dirname "$ZIG")/lib/libc/musl/COPYRIGHT" "$OUT/COPYRIGHT.musl"
file "$OUT/iperf3-$ARCH" 2>/dev/null || true
ls -l "$OUT/iperf3-$ARCH"
