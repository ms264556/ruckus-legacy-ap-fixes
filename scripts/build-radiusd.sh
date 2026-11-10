#!/bin/sh
#
# build-radiusd.sh - build a static rmc-radiusd-<arch>: hostapd's integrated RADIUS/EAP server (PEAP/MSCHAPv2,
# TTLS/PAP, TTLS/MSCHAPv2, EAP-TLS) for checking WPA2/WPA3-Enterprise usernames and passwords on the AP itself.
# The AP's own hostapd sends its Access-Requests to it on 127.0.0.2 (127.0.0.1 means TCP to 2.x, 3.x and 5.1).
#
# hostapd is the upstream 2.11 release with the changes of src/radiusd/apply-patches.py, linked statically against
# wolfSSL 5.7 (its hostapd profile, --enable-wpas, which has MD4 and DES for MSCHAPv2) and musl, soft-float, with Zig's
# bundled clang. wolfSSL's autotools build needs autoconf, automake and libtool on the build host, the .gz zopfli:
#
#   arm   32-bit ARMv7 (3.6 to 7.x ARM APs)
#   mips  MIPS32r2 big-endian
#   ppc   32-bit PowerPC big-endian (R700 family)
#
# Usage: ARCH=arm|mips|ppc ./scripts/build-radiusd.sh
#   output: out/radiusd/rmc-radiusd-<arch> and rmc-radiusd-<arch>.gz (zopfli), plus the licences the binary carries:
#   out/radiusd/COPYING.hostapd (BSD-3-Clause), out/radiusd/COPYING.wolfssl (GPL-2.0-or-later), out/radiusd/COPYRIGHT.musl (MIT),
#   and out/radiusd/rmc-radiusd-src.tar.xz: wolfSSL's GPL makes the binary GPL-2.0-or-later as a whole, and that archive
#   is its corresponding source (the same file for every ARCH; see below).
#        ZIG=/path/to/zig to use an already unpacked Zig 0.14.1;
#        DOWNLOADS=<dir> to keep the downloaded tarballs (default: a temp dir);
#        KEEP_WORK=1 to leave the work folder (/tmp/rmc-radiusd-build-<arch>) for inspection.
set -eu

ARCH=${ARCH:?set ARCH=arm|mips|ppc}
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${OUT:-$BASE/out/radiusd}

HOSTAPD_VERSION=2.11
HOSTAPD_SHA256=2b3facb632fd4f65e32f4bf82a76b4b72c501f995a4f62e330219fe7aed1747a
HOSTAPD_URL=https://w1.fi/releases/hostapd-$HOSTAPD_VERSION.tar.gz
WOLFSSL_VERSION=5.7.6
WOLFSSL_SHA256=52b1e439e30d1ed8162a16308a8525a862183b67aa30373b11166ecbab000d63
WOLFSSL_URL=https://github.com/wolfSSL/wolfssl/archive/refs/tags/v$WOLFSSL_VERSION-stable.tar.gz
ZIG_VERSION=0.14.1
case "$(uname -m)" in
    x86_64)  ZIG_HOST=x86_64-linux;  ZIG_SHA256=24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c ;;
    aarch64) ZIG_HOST=aarch64-linux; ZIG_SHA256=f7a654acc967864f7a050ddacfaa778c7504a0eca8d2b678839c21eea47c992b ;;
    *) echo "error: no pinned Zig for build host $(uname -m)" >&2; exit 1 ;;
esac
ZIG_URL=https://ziglang.org/download/$ZIG_VERSION/zig-$ZIG_HOST-$ZIG_VERSION.tar.xz

case "$ARCH" in
    arm)  TARGET=arm-linux-musleabi;     MCPU=generic+v7a;          CHOST=arm-linux-musleabi ;;
    mips) TARGET=mips-linux-musleabi;    MCPU=mips32r2+soft_float;  CHOST=mips-linux-musl ;;
    ppc)  TARGET=powerpc-linux-musleabi; MCPU=440-isel;             CHOST=powerpc-linux-musl ;;
    *) echo "error: unknown ARCH=$ARCH (expected arm|mips|ppc)" >&2; exit 1 ;;
esac

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
export LC_ALL=C TZ=UTC

# A fixed work folder, not mktemp's: a library's source paths can end up in the binary, so a random folder name would
# change every build's bytes. Two builds of one architecture at once would share it.
WORK=/tmp/rmc-radiusd-build-$ARCH
rm -rf "$WORK"
mkdir -p "$WORK"
[ -n "${KEEP_WORK:-}" ] || trap 'rm -rf "$WORK"' EXIT
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
fetch "$WOLFSSL_URL" "$WOLFSSL_SHA256" "wolfssl-$WOLFSSL_VERSION.tar.gz"
tar -C "$WORK" -xzf "$DL/hostapd-$HOSTAPD_VERSION.tar.gz"
tar -C "$WORK" -xzf "$DL/wolfssl-$WOLFSSL_VERSION.tar.gz"

# The binary's corresponding source (wolfSSL is GPL): hostapd and wolfSSL without what this build never compiles (every
# other C file; and in wolfSSL other platforms, assembly, tests, examples and docs; every header, makefile, automake file
# and template is kept), and this repository's build script and changes. The build below runs from exactly these pruned
# trees, so the archive is complete by construction: a file the build needs and the pruning dropped stops it.
HAP=$WORK/hostapd-$HOSTAPD_VERSION
WOLF=$WORK/wolfssl-$WOLFSSL_VERSION-stable

# keep_c <dir> <list>: deletes every .c file below <dir> whose path relative to it is not in <list> (space-separated,
# with a leading and a trailing space).
keep_c() {
    find "$1" -type f -name '*.c' | while read -r f; do
        case "$2" in *" ${f#"$1"/} "*) ;; *) rm -f "$f" ;; esac
    done
}

# hostapd: the C files of hostapd/.config (the driver-less RADIUS/EAP server).
keep_c "$HAP" " hostapd/config_file.c hostapd/eap_register.c hostapd/main.c src/ap/ap_config.c src/ap/ap_drv_ops.c src/ap/ap_mlme.c src/ap/authsrv.c src/ap/beacon.c src/ap/bss_load.c src/ap/drv_callbacks.c src/ap/eap_user_db.c src/ap/hostapd.c src/ap/ieee802_11_auth.c src/ap/ieee802_11_ht.c src/ap/ieee802_11_shared.c src/ap/ieee802_1x.c src/ap/neighbor_db.c src/ap/pmksa_cache_auth.c src/ap/preauth_auth.c src/ap/rrm.c src/ap/sta_info.c src/ap/tkip_countermeasures.c src/ap/utils.c src/ap/wpa_auth.c src/ap/wpa_auth_glue.c src/ap/wpa_auth_ie.c src/common/hw_features_common.c src/common/ieee802_11_common.c src/common/ptksa_cache.c src/common/wpa_common.c src/crypto/crypto_wolfssl.c src/crypto/ms_funcs.c src/crypto/random.c src/crypto/sha1-prf.c src/crypto/sha1-tlsprf.c src/crypto/sha256-prf.c src/crypto/sha256-tlsprf.c src/crypto/tls_wolfssl.c src/drivers/driver_common.c src/drivers/driver_none.c src/drivers/drivers.c src/eap_common/chap.c src/eap_common/eap_common.c src/eap_common/eap_peap_common.c src/eap_server/eap_server.c src/eap_server/eap_server_identity.c src/eap_server/eap_server_methods.c src/eap_server/eap_server_mschapv2.c src/eap_server/eap_server_peap.c src/eap_server/eap_server_tls.c src/eap_server/eap_server_tls_common.c src/eap_server/eap_server_ttls.c src/eapol_auth/eapol_auth_sm.c src/l2_packet/l2_packet_none.c src/radius/radius.c src/radius/radius_client.c src/radius/radius_das.c src/radius/radius_server.c src/utils/common.c src/utils/crc32.c src/utils/eloop.c src/utils/ip_addr.c src/utils/os_unix.c src/utils/wpa_debug.c src/utils/wpabuf.c "

# wolfSSL: other platforms, tests, examples, docs and helper scripts go whole (automake files and templates stay)...
for d in IDE certs doc tests testsuite examples wolfcrypt/test wolfcrypt/benchmark wolfcrypt/src/port wrapper mqx mplabx \
         zephyr linuxkm RTOS sslSniffer Docker debian rpm .github cmake support scripts; do
    [ -e "$WOLF/$d" ] && find "$WOLF/$d" -type f ! -name '*.am' ! -name '*.in' -delete
done
# ...as does every assembly file, and every C file this configuration neither compiles nor #includes (src/ssl.c includes
# bio.c, conf.c, pk.c, x509*.c and the ssl_*.c below; wolfcrypt's asm.c, evp.c and misc.c are included by others).
find "$WOLF/wolfcrypt/src" -maxdepth 1 -type f \( -name '*.S' -o -name '*.asm' -o -name '*.i' \) -delete
keep_c "$WOLF" " src/bio.c src/conf.c src/crl.c src/internal.c src/keys.c src/ocsp.c src/pk.c src/ssl.c src/ssl_asn1.c src/ssl_bn.c src/ssl_certman.c src/ssl_crypto.c src/ssl_load.c src/ssl_misc.c src/ssl_p7p12.c src/ssl_sess.c src/tls.c src/wolfio.c src/x509.c src/x509_str.c wolfcrypt/src/aes.c wolfcrypt/src/arc4.c wolfcrypt/src/asm.c wolfcrypt/src/asn.c wolfcrypt/src/cmac.c wolfcrypt/src/coding.c wolfcrypt/src/cpuid.c wolfcrypt/src/des3.c wolfcrypt/src/dh.c wolfcrypt/src/dsa.c wolfcrypt/src/ecc.c wolfcrypt/src/error.c wolfcrypt/src/evp.c wolfcrypt/src/hash.c wolfcrypt/src/hmac.c wolfcrypt/src/kdf.c wolfcrypt/src/logging.c wolfcrypt/src/md4.c wolfcrypt/src/md5.c wolfcrypt/src/memory.c wolfcrypt/src/misc.c wolfcrypt/src/pkcs12.c wolfcrypt/src/pwdbased.c wolfcrypt/src/random.c wolfcrypt/src/rsa.c wolfcrypt/src/sha.c wolfcrypt/src/sha256.c wolfcrypt/src/sha512.c wolfcrypt/src/signature.c wolfcrypt/src/sp_int.c wolfcrypt/src/wc_encrypt.c wolfcrypt/src/wc_port.c wolfcrypt/src/wolfmath.c "
mkdir -p "$WORK/srcpkg/ruckus-legacy-ap-fixes/scripts" "$WORK/srcpkg/ruckus-legacy-ap-fixes/src"
cp -R "$HAP" "$WOLF" "$WORK/srcpkg/"
cp "$BASE/scripts/build-radiusd.sh" "$WORK/srcpkg/ruckus-legacy-ap-fixes/scripts/"
cp -R "$BASE/src/radiusd" "$WORK/srcpkg/ruckus-legacy-ap-fixes/src/"
cat > "$WORK/srcpkg/README" <<EOF
rmc-radiusd corresponding source: hostapd $HOSTAPD_VERSION (BSD-3-Clause) and wolfSSL $WOLFSSL_VERSION
(GPL-2.0-or-later), each without the files this build does not compile, and ruckus-legacy-ap-fixes'
scripts/build-radiusd.sh and src/radiusd (MIT). The script builds the binary from these trees after applying
src/radiusd/apply-patches.py to hostapd; https://github.com/ms264556/ruckus-legacy-ap-fixes has the rest of it.
EOF
tar -C "$WORK/srcpkg" --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -cf - . \
    | xz -9e -T1 > "$OUT/rmc-radiusd-src.tar.xz"

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

# wolfSSL: static only, its hostapd profile, single-threaded (hostapd is; it also keeps out the 64-bit atomics 32-bit
# MIPS and PowerPC lack), portable C, no tests or examples. PEAP and TTLS run TLS 1.2 (as the controller's own EAP server
# does) with AES, so TLS 1.3 and ChaCha20/Poly1305 are left out: about a tenth of the binary.
cd "$WOLF"
./autogen.sh >"$WORK/ssl-configure.log" 2>&1 || { tail -40 "$WORK/ssl-configure.log" >&2; exit 1; }
./configure --host="$CHOST" --enable-static --disable-shared --enable-wpas --enable-singlethreaded \
    --disable-asm --disable-examples --disable-crypttests --disable-benchmark --enable-reproducible-build \
    --disable-tls13 --disable-chacha --disable-poly1305 \
    CC="$WORK/zig-cc" AR="$WORK/zig-ar" RANLIB="$WORK/zig-ranlib" CFLAGS="$SIZE_FLAGS" >>"$WORK/ssl-configure.log" 2>&1 \
    || { tail -40 "$WORK/ssl-configure.log" >&2; exit 1; }
make -j"$(nproc)" src/libwolfssl.la >"$WORK/ssl-make.log" 2>&1 || { tail -40 "$WORK/ssl-make.log" >&2; exit 1; }

# hostapd: RADIUS/EAP server only.
cd "$HAP"
python3 "$BASE/src/radiusd/apply-patches.py" "$PWD" >/dev/null
cp "$BASE/src/radiusd/hostapd.config" hostapd/.config
make -C hostapd -j"$(nproc)" hostapd V=1 \
    CC="$WORK/zig-cc" \
    EXTRA_CFLAGS="$SIZE_FLAGS -I$WOLF" \
    LDFLAGS="-static -Wl,--gc-sections -s -L$WOLF/src/.libs" \
    >"$WORK/hostapd-make.log" 2>&1 || { grep -E "error|Error" "$WORK/hostapd-make.log" | head -30 >&2; tail -20 "$WORK/hostapd-make.log" >&2; exit 1; }

cp -f hostapd/hostapd "$OUT/rmc-radiusd-$ARCH"
# The same, gzipped as tightly as gzip allows (zopfli, deterministic): what an AP keeps on flash when the binary itself
# does not fit, unpacked with gunzip or zlib's minigzip.
zopfli -c --i100 "$OUT/rmc-radiusd-$ARCH" > "$OUT/rmc-radiusd-$ARCH.gz"
cp -f COPYING "$OUT/COPYING.hostapd"
cp -f "$WORK/wolfssl-$WOLFSSL_VERSION-stable/COPYING" "$OUT/COPYING.wolfssl"
cp -f "$(dirname "$ZIG")/lib/libc/musl/COPYRIGHT" "$OUT/COPYRIGHT.musl"
file "$OUT/rmc-radiusd-$ARCH" 2>/dev/null || true
ls -l "$OUT/rmc-radiusd-$ARCH"
