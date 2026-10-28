/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * wlanpatch.c (ARM) - runtime wlan.ko patcher for 3.14.43 ARMv7 APs.
 *
 * Carries the mesh RX VLAN inner-EtherType fix (bne -> b) for the ap-arm-*
 * families (ZoneDirector 10.5.1.x and SmartZone 5.2.2 share the bug).  The
 * ldrh/rev16/uxth/cmp/bne tail is identical in both builds; only the first
 * ldr differs because struct sk_buff moved by 12 bytes, so two signatures are
 * tried and whichever is present is patched.
 *
 * The MCS/HT-cap bug is NOT present in the ARM driver (its ieee80211_add_htcap
 * encodes the Tx MCS Set byte correctly), so there is no MCS rule here; that
 * fix is MIPS-only.  See docs/mcs-htcap.md.
 *
 *   insmod wlanpatch-arm.ko wlan_base=0x... wlan_size=...
 */
#include "../common/patch_engine.h"

/* ---- 3.14.43 module parameters ------------------------------------------- */

struct kernel_param;
struct kernel_param_ops {
    int (*set)(const char *val, const struct kernel_param *kp);
    int (*get)(char *buffer, const struct kernel_param *kp);
    void (*free)(void *arg);
};
struct kernel_param {
    const char *name;
    const struct kernel_param_ops *ops;
    unsigned short perm;
    signed char level;
    unsigned char flags;
    union { void *arg; const void *str; const void *arr; };
};

extern const struct kernel_param_ops param_ops_ulong;
extern unsigned long kallsyms_lookup_name(const char *name);
extern int printk(const char *fmt, ...);

unsigned long wlan_base;
unsigned long wlan_size;

static const struct kernel_param __param_wlan_base
    __attribute__((section("__param"), used)) = {
        .name = "wlan_base", .ops = &param_ops_ulong, .arg = &wlan_base
    };
static const struct kernel_param __param_wlan_size
    __attribute__((section("__param"), used)) = {
        .name = "wlan_size", .ops = &param_ops_ulong, .arg = &wlan_size
    };

/* ---- ARM instruction-stream flush (resolved via kallsyms) ---------------- */

typedef void (*clean_area_fn)(void *addr, int size);
typedef void (*flush_icache_fn)(void);

void wlanpatch_flush(volatile u32 *p)
{
    static clean_area_fn clean;
    static flush_icache_fn icache;

    if (!clean)
        clean = (clean_area_fn)kallsyms_lookup_name("cpu_v7_dcache_clean_area");
    if (!icache)
        icache = (flush_icache_fn)kallsyms_lookup_name("v7_flush_icache_all");
    if (clean)
        clean((void *)p, 4);
    if (icache)
        icache();
}

/* ---- rules: mesh-vlan-rx (ZD 10.5.1.x and SZ 5.2.2) ---------------------- *
 * Little-endian byte order.  The six words are:
 *   ldr r3,[rN,#...]   (differs by build -> two signatures)
 *   ldrh r3,[r3,#12] ; rev16 r3,r3 ; uxth r3,r3 ; cmp r3,#0x8100 ; bne <skip>
 * The bne condition byte (index 23) is masked so the window still matches
 * after the b rewrite, making rmmod able to revert.
 */
static const u8 sig_mesh_zd[24] = {
    0x18,0x31,0x94,0xe5, 0xbc,0x30,0xd3,0xe1, 0xb3,0x3f,0xbf,0xe6,
    0x73,0x30,0xff,0xe6, 0x81,0x0c,0x53,0xe3, 0x02,0x00,0x00,0x1a,
};
static const u8 sig_mesh_sz[24] = {
    0x24,0x31,0x96,0xe5, 0xbc,0x30,0xd3,0xe1, 0xb3,0x3f,0xbf,0xe6,
    0x73,0x30,0xff,0xe6, 0x81,0x0c,0x53,0xe3, 0x02,0x00,0x00,0x1a,
};
static const u8 msk_mesh[24] = {
    1,1,1,1, 1,1,1,1, 1,1,1,1,
    1,1,1,1, 1,1,1,1, 1,1,1,0,   /* index 23: bne condition byte */
};
static const struct edit edit_mesh[] = {
    { 20, 0x1a000002u, 0xea000002u },   /* bne -> b */
};

static const struct rule rules[] = {
    { "mesh-vlan-rx-zd", sig_mesh_zd, msk_mesh, sizeof(sig_mesh_zd), edit_mesh, 1 },
    { "mesh-vlan-rx-sz", sig_mesh_sz, msk_mesh, sizeof(sig_mesh_sz), edit_mesh, 1 },
};
#define N_RULES (sizeof(rules) / sizeof(rules[0]))

int init_module(void)
{
    struct mp_tally t;

    if (!wlan_base || !wlan_size)
        return -22;

    mp_apply(rules, N_RULES, wlan_base, wlan_size, &t);
    printk("wlanpatch: matched=%d written=%d already=%d failed=%d\n",
           t.matched, t.written, t.already, t.failed);

    if (t.failed)
        return -5;
    if (!t.matched)
        return -19;
    return 0;
}

void cleanup_module(void)
{
    mp_revert(rules, N_RULES, wlan_base, wlan_size);
}
