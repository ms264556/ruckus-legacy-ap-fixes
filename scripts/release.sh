#!/bin/sh
#
# release.sh - assemble release assets from the packaged dist/ tree.
#
# Produces release/ with, for each architecture built:
#   wlanpatch-<arch>.ko                            the loadable module (loose)
#   ruckus-legacy-ap-fixes-<arch>-<ver>.tar.gz     module + hook.sh + manifest.env
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

( cd "$REL" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' \
    | sort -z | xargs -0 sha256sum > SHA256SUMS )

echo "--- release/SHA256SUMS ---"
cat "$REL/SHA256SUMS"
