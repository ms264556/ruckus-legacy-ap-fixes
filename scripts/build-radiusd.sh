#!/bin/sh
#
# build-radiusd.sh - build a static rmc-radiusd-<arch>: hostapd's integrated RADIUS/EAP server (PEAP/MSCHAPv2,
# TTLS/PAP, TTLS/MSCHAPv2, EAP-TLS) for checking WPA2/WPA3-Enterprise usernames and passwords on the AP itself.
# The AP's own hostapd sends its Access-Requests to it on 127.0.0.2 (127.0.0.1 means TCP to 2.x, 3.x and 5.1).
#
# hostapd is the upstream 2.11 release with the changes of src/radiusd/apply-patches.py, linked statically against
# OpenSSL 3.5 (legacy provider built in, for MD4 and DES) and musl, soft-float, with Zig's bundled clang:
#
#   arm   32-bit ARMv7 (3.6 to 7.x ARM APs)
#   mips  MIPS32r2 big-endian
#   ppc   32-bit PowerPC big-endian (R700 family)
#
# Usage: ARCH=arm|mips|ppc ./scripts/build-radiusd.sh
#   output: out/radiusd/rmc-radiusd-<arch>, plus the licences the binary carries:
#   out/radiusd/COPYING.hostapd (BSD-3-Clause), out/radiusd/LICENSE.openssl (Apache-2.0), out/radiusd/COPYRIGHT.musl (MIT)
#        ZIG=/path/to/zig to use an already unpacked Zig 0.14.1;
#        DOWNLOADS=<dir> to keep the downloaded tarballs (default: a temp dir).
set -eu

ARCH=${ARCH:?set ARCH=arm|mips|ppc}
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${OUT:-$BASE/out/radiusd}

HOSTAPD_VERSION=2.11
HOSTAPD_SHA256=2b3facb632fd4f65e32f4bf82a76b4b72c501f995a4f62e330219fe7aed1747a
HOSTAPD_URL=https://w1.fi/releases/hostapd-$HOSTAPD_VERSION.tar.gz
OPENSSL_VERSION=3.5.4
OPENSSL_SHA256=967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99
OPENSSL_URL=https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz
ZIG_VERSION=0.14.1
case "$(uname -m)" in
    x86_64)  ZIG_HOST=x86_64-linux;  ZIG_SHA256=24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c ;;
    aarch64) ZIG_HOST=aarch64-linux; ZIG_SHA256=f7a654acc967864f7a050ddacfaa778c7504a0eca8d2b678839c21eea47c992b ;;
    *) echo "error: no pinned Zig for build host $(uname -m)" >&2; exit 1 ;;
esac
ZIG_URL=https://ziglang.org/download/$ZIG_VERSION/zig-$ZIG_HOST-$ZIG_VERSION.tar.xz

case "$ARCH" in
    arm)  TARGET=arm-linux-musleabi;     MCPU=generic+v7a;          OSSL_TARGET=linux-armv4 ;;
    mips) TARGET=mips-linux-musleabi;    MCPU=mips32r2+soft_float;  OSSL_TARGET=linux-mips32 ;;
    ppc)  TARGET=powerpc-linux-musleabi; MCPU=440-isel;             OSSL_TARGET=linux-ppc ;;
    *) echo "error: unknown ARCH=$ARCH (expected arm|mips|ppc)" >&2; exit 1 ;;
esac

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
export LC_ALL=C TZ=UTC

# A fixed work folder, not mktemp's: OpenSSL keeps source paths and its compiler command line in the binary, so a
# random folder name changes every build's bytes. Two builds of one architecture at once would share it.
WORK=/tmp/rmc-radiusd-build-$ARCH
rm -rf "$WORK"
mkdir -p "$WORK"
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
fetch "$HOSTAPD_URL" "$HOSTAPD_SHA256" "hostapd-$HOSTAPD_VERSION.tar.gz"
fetch "$OPENSSL_URL" "$OPENSSL_SHA256" "openssl-$OPENSSL_VERSION.tar.gz"
tar -C "$WORK" -xzf "$DL/hostapd-$HOSTAPD_VERSION.tar.gz"
tar -C "$WORK" -xzf "$DL/openssl-$OPENSSL_VERSION.tar.gz"

# Build tools want single-word commands.
for tool in cc ar ranlib; do
    case $tool in
        cc) cmd="cc -target $TARGET -mcpu=$MCPU" ;;
        *)  cmd=$tool ;;
    esac
    printf '#!/bin/sh\nexec "%s" %s "$@"\n' "$ZIG" "$cmd" > "$WORK/zig-$tool"
    chmod +x "$WORK/zig-$tool"
done
export ZIG_GLOBAL_CACHE_DIR=$WORK/zig-cache ZIG_LOCAL_CACHE_DIR=$WORK/zig-cache
SIZE_FLAGS="-Os -ffunction-sections -fdata-sections"

# OpenSSL: static only, legacy provider compiled in (no-module), nothing hostapd does not use. hostapd is single-threaded,
# so no-threads, which also keeps out the 64-bit atomics 32-bit MIPS and PowerPC lack (__atomic_is_lock_free).
SSL=$WORK/ssl
cd "$WORK/openssl-$OPENSSL_VERSION"
./Configure "$OSSL_TARGET" --prefix="$SSL" --libdir=lib --openssldir=/etc/ssl \
    no-shared no-module no-asm no-tests no-docs no-apps no-engine no-dso no-async no-afalgeng no-quic no-ssl3 \
    no-comp no-srp no-sctp no-ui-console no-padlockeng no-capieng no-autoload-config no-threads \
    CC="$WORK/zig-cc" AR="$WORK/zig-ar" RANLIB="$WORK/zig-ranlib" CFLAGS="$SIZE_FLAGS" >"$WORK/ssl-configure.log" 2>&1 \
    || { tail -40 "$WORK/ssl-configure.log" >&2; exit 1; }
make -j"$(nproc)" build_libs >"$WORK/ssl-make.log" 2>&1 || { tail -40 "$WORK/ssl-make.log" >&2; exit 1; }
make install_dev >>"$WORK/ssl-make.log" 2>&1 || { tail -40 "$WORK/ssl-make.log" >&2; exit 1; }

# hostapd: RADIUS/EAP server only.
cd "$WORK/hostapd-$HOSTAPD_VERSION"
python3 "$BASE/src/radiusd/apply-patches.py" "$PWD" >/dev/null
cp "$BASE/src/radiusd/hostapd.config" hostapd/.config
make -C hostapd -j"$(nproc)" hostapd V=1 \
    CC="$WORK/zig-cc" \
    EXTRA_CFLAGS="$SIZE_FLAGS -I$SSL/include" \
    LDFLAGS="-static -Wl,--gc-sections -s -L$SSL/lib" \
    >"$WORK/hostapd-make.log" 2>&1 || { grep -E "error|Error" "$WORK/hostapd-make.log" | head -30 >&2; tail -20 "$WORK/hostapd-make.log" >&2; exit 1; }

cp -f hostapd/hostapd "$OUT/rmc-radiusd-$ARCH"
cp -f COPYING "$OUT/COPYING.hostapd"
cp -f "$WORK/openssl-$OPENSSL_VERSION/LICENSE.txt" "$OUT/LICENSE.openssl"
cp -f "$(dirname "$ZIG")/lib/libc/musl/COPYRIGHT" "$OUT/COPYRIGHT.musl"
file "$OUT/rmc-radiusd-$ARCH" 2>/dev/null || true
ls -l "$OUT/rmc-radiusd-$ARCH"
