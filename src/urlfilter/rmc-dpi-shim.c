// SPDX-License-Identifier: MIT
/*
 * rmc-dpi-shim.so - lets a small SmartZone 3.6 AP run avpd's DPI engine, which its web (URL) filter depends on.
 *
 * avpd sets its DPI flag once at start, only when librsm's rsm_mem_support_tm() passes; that is
 * rsm_check_mem_support(200000), i.e. MemTotal above 200 000 kB, so 128 MB models (H500, C500, the ZF7372 family)
 * never inspect a flow, and their web filter never asks for a category (docs/firmware/content-filtering.md in the
 * controller repository). avpd imports rsm_mem_support_tm from librsm.so, so preloading this object when avpd starts
 * (LD_PRELOAD=/tmp/.../rmc-dpi-shim.so /usr/sbin/avpd -i cif0 -D) answers "supported" for avpd alone; nothing else on
 * the AP changes, and a reboot or an avpd restart without it puts the firmware back.
 *
 * No libc: it is loaded into a uClibc process, and this file needs nothing from one.
 */
int rsm_mem_support_tm(void)
{
    return 1;
}
