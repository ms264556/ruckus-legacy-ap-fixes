#!/bin/sh
#
# package.sh - assemble dist/ from the built modules and the device-side files.
#
# For each architecture built in out/<arch>/ it makes a dist/<arch>/ bundle
# (module + hook.sh + a filled manifest.env) and writes a single top-level
# dist/SHA256SUMS over every file. CI attests dist/* and attaches it to the
# release.
set -eu

BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIST=$BASE/dist
export LC_ALL=C

rm -rf "$DIST"
mkdir -p "$DIST"

emit() {
    arch=$1
    kernel=$2
    ko=$BASE/out/$arch/wlanpatch-$arch.ko
    [ -f "$ko" ] || return 0
    d=$DIST/$arch
    mkdir -p "$d"
    cp -f "$ko" "$d/wlanpatch-$arch.ko"
    cp -f "$BASE/deploy/hook.sh" "$d/hook.sh"
    sha=$(sha256sum "$d/wlanpatch-$arch.ko" | awk '{print $1}')
    sed -e "s|@KO@|wlanpatch-$arch.ko|g" \
        -e "s|@SHA@|$sha|g" \
        -e "s|@KERNEL@|$kernel|g" \
        "$BASE/deploy/manifest.env.in" > "$d/manifest.env"
    echo "packaged $arch (sha $sha)"
}

emit mips 2.6.32.24
emit ppc  2.6.32.24
emit arm  3.14.43

( cd "$DIST" && find . -type f ! -name SHA256SUMS -print0 \
    | sort -z | xargs -0 sha256sum > SHA256SUMS )

echo "--- dist/SHA256SUMS ---"
cat "$DIST/SHA256SUMS"
