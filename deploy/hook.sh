#!/bin/sh
# AP start hook: load the wlanpatch module after wlan.ko is loaded.
#
# Architecture-independent: the module filename, expected kernel and expected
# module hash all come from manifest.env next to this hook. A sentinel guards
# against a previous run that did not finish; the kernel, module hash and wlan
# presence are checked; and the live wlan base/size from /proc/modules are
# passed as module parameters. A trial is confirmed only after 90 s with the
# module and wlan still loaded; an unconfirmed trial leaves the stock driver.
#
# Install: copy the bundle (module, hook.sh, manifest.env) to BASE below, then
# copy hook.sh to /writable/data/scripts/start/00-ruckus-ap-fixes.
BASE=/writable/ruckus-ap-fixes
SENTINEL=$BASE/hook.running
STATE=$BASE/state
LOG=$BASE/hook.log
MANIFEST=$BASE/manifest.env

mkdir -p "$BASE"
if [ -e "$SENTINEL" ]; then
    echo "=== $(date) sentinel present: previous hook run did not finish; skipping" >> "$LOG"
    exit 0
fi
touch "$SENTINEL"
busybox sync 2>/dev/null || true

log() { echo "$*" >> "$LOG"; }
done_ok() { rm -f "$SENTINEL"; busybox sync 2>/dev/null || true; exit 0; }

MODULE=
EXPECTED_SHA=
EXPECTED_KERNEL=
if [ -f "$MANIFEST" ]; then
    # shellcheck disable=SC1090
    . "$MANIFEST"
fi

if [ -z "$MODULE" ] || [ -z "$EXPECTED_SHA" ] || [ -z "$EXPECTED_KERNEL" ]; then
    log "=== $(date) manifest.env incomplete; leaving stock"
    done_ok
fi
MODPATH=$BASE/$MODULE

if [ "$(uname -r)" != "$EXPECTED_KERNEL" ]; then
    log "=== $(date) kernel $(uname -r) != $EXPECTED_KERNEL; leaving stock"
    done_ok
fi

if [ ! -f "$MODPATH" ]; then
    log "=== $(date) $MODPATH missing; leaving stock"
    done_ok
fi

if ! echo "$EXPECTED_SHA  $MODPATH" | sha256sum -c - >/dev/null 2>&1; then
    log "=== $(date) $MODULE hash mismatch; leaving stock"
    done_ok
fi

if ! grep -q '^wlan ' /proc/modules 2>/dev/null; then
    log "=== $(date) wlan not loaded at hook time; leaving stock"
    done_ok
fi

wlan_line=$(grep '^wlan ' /proc/modules 2>/dev/null)
base=$(echo "$wlan_line" | awk '{print $6}')
size=$(echo "$wlan_line" | awk '{print $2}')
if [ -z "$base" ] || [ -z "$size" ]; then
    log "=== $(date) wlan base/size missing (base=$base size=$size); leaving stock"
    done_ok
fi

if lsmod 2>/dev/null | grep -q '^wlanpatch '; then
    log "=== $(date) wlanpatch already loaded; nothing to do"
    done_ok
fi

{ echo "confirmed=0"; echo "attempts=1"; } > "$STATE"
busybox sync 2>/dev/null || true

log "=== $(date) loading $MODULE (wlan base $base size $size)"
insmod "$MODPATH" "wlan_base=$base" "wlan_size=$size" >> "$LOG" 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
    log "insmod failed rc=$rc; leaving stock"
    done_ok
fi

log "insmod ok; starting confirmation check"
(
    sleep 90
    if lsmod 2>/dev/null | grep -q '^wlanpatch ' && grep -q '^wlan ' /proc/modules 2>/dev/null; then
        { echo "confirmed=1"; echo "attempts=1"; } > "$STATE"
        log "confirmed at $(date)"
    else
        log "NOT confirmed at $(date): wlanpatch or wlan missing"
    fi
    busybox sync 2>/dev/null || true
) &

done_ok
