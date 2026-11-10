#!/bin/sh
#
# release.sh - assemble release assets from the packaged dist/ tree.
#
# Produces release/ with, for each architecture built:
#   wlanpatch-<arch>.ko                            the loadable module (loose)
#   ruckus-legacy-ap-fixes-<arch>-<ver>.tar.gz     module + hook.sh + manifest.env
#   iperf3-<arch>, LICENSE.iperf3, COPYRIGHT.musl    static iperf3 (scripts/build-iperf3.sh), when built
#   rmc-urlfilter-<arch>                           the uf_agent stand-in (scripts/build-urlfilter.sh), when built
#   rmc-dpi-shim-<arch>.so                         avpd's DPI memory-gate shim (scripts/build-urlfilter.sh), when built
#   rmc-radiusd-<arch>, COPYING.hostapd, LICENSE.openssl   hostapd's RADIUS server (scripts/build-radiusd.sh), when built
# plus a single release/SHA256SUMS over all of them. CI uploads release/,
# attests every file in it, and attaches them to the GitHub release.
#
# Usage: ./scripts/release.sh <version>    (run scripts/package.sh first)
set -eu

VER=${1:?usage: release.sh <version>}
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIST=$BASE/dist
REL=$BASE/release
export LC_ALL=C
EPOCH=${SOURCE_DATE_EPOCH:-0}

[ -d "$DIST" ] || { echo "error: no dist/; run scripts/package.sh first" >&2; exit 1; }

rm -rf "$REL"
mkdir -p "$REL"

emit() {
    arch=$1
    ko=$DIST/$arch/wlanpatch-$arch.ko
    [ -f "$ko" ] || return 0
    cp -f "$ko" "$REL/wlanpatch-$arch.ko"
    # Deterministic tarball of the install bundle.
    tar --sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
        -C "$DIST/$arch" -czf "$REL/ruckus-legacy-ap-fixes-$arch-$VER.tar.gz" .
    echo "release asset: wlanpatch-$arch.ko + ruckus-legacy-ap-fixes-$arch-$VER.tar.gz"
}

emit mips
emit ppc
emit arm

# The static iperf3 builds (scripts/build-iperf3.sh), loose, with the licences they carry.
for f in iperf3-mips iperf3-ppc iperf3-arm LICENSE.iperf3 COPYRIGHT.musl; do
    [ -f "$BASE/out/iperf3/$f" ] || continue
    cp -f "$BASE/out/iperf3/$f" "$REL/$f"
    echo "release asset: $f"
done

# The uf_agent stand-in and the DPI shim (scripts/build-urlfilter.sh), loose; the agent links musl, whose licence ships
# with iperf3, and the shim links nothing.
for f in rmc-urlfilter-mips rmc-urlfilter-ppc rmc-urlfilter-arm rmc-dpi-shim-mips.so rmc-dpi-shim-ppc.so rmc-dpi-shim-arm.so; do
    [ -f "$BASE/out/urlfilter/$f" ] || continue
    cp -f "$BASE/out/urlfilter/$f" "$REL/$f"
    echo "release asset: $f"
done

# hostapd's RADIUS server (scripts/build-radiusd.sh), loose, with the licences it carries beside musl's.
for f in rmc-radiusd-mips rmc-radiusd-ppc rmc-radiusd-arm COPYING.hostapd LICENSE.openssl; do
    [ -f "$BASE/out/radiusd/$f" ] || continue
    cp -f "$BASE/out/radiusd/$f" "$REL/$f"
    echo "release asset: $f"
done

( cd "$REL" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' \
    | sort -z | xargs -0 sha256sum > SHA256SUMS )

echo "--- release/SHA256SUMS ---"
cat "$REL/SHA256SUMS"
