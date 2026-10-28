/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * wlanpatch.c (PowerPC) - runtime wlan.ko patcher for 2.6.32.24 PPC APs
 * (the R700 / SC8800 / ZF7781CM / ZF7782 / ZF7982 family).
 *
 * The PowerPC Atheros driver carries the same MCS/HT-cap bug as the MIPS one:
 * ieee80211_add_htcap() writes the Tx MCS Set parameters byte (MCS-set byte 12,
 * at 0xf(r31) in the frame) with the wrong bits and never sets "Tx MCS Set
 * Defined", so a 7.x root rejects the association. Three sites, one per
 * Tx-stream path:
 *     2 streams  ori r0,r0,0x10 -> 0x01  (Tx MCS Set Defined)
 *     3 streams  ori r0,r0,0x20 -> 0x01  (Tx MCS Set Defined)
 *     Rx != Tx   ori r0,r0,0x40 -> 0x02  (Tx Rx MCS Set Not Equal)
 *
 * PPC ori r0,r0,UIMM encodes as 0x60000000|UIMM, so the rewrites are
 * 0x60000010->0x60000001, 0x60000020->0x60000001, 0x60000040->0x60000002.
 * The Tx Maximum Spatial Streams field is reserved (0) unless Not Equal is
 * set; the 7.x parser rejects a byte that has it set with Not Equal clear.
 * See docs/mcs-htcap.md. The mesh-vlan-rx fix is not included here (not yet
 * confirmed on this family).
 *
 *   insmod wlanpatch-ppc.ko wlan_base=0x... wlan_size=...
 */
#include "../common/patch_engine.h"

/* ---- 2.6.32 module parameters (same struct as the MIPS build) ------------ */

struct kernel_param {
    const char *name;
    unsigned short perm;
    unsigned short flags;
    int (*set)(const char *val, struct kernel_param *kp);
    int (*get)(char *buffer, struct kernel_param *kp);
    union { void *arg; } u;
};

extern int param_set_ulong(const char *val, struct kernel_param *kp);
extern int param_get_ulong(char *buffer, struct kernel_param *kp);
extern int printk(const char *fmt, ...);

unsigned long wlan_base;
unsigned long wlan_size;

static const char param_name_base[] = "wlan_base";
static const char param_name_size[] = "wlan_size";

static struct kernel_param __param_wlan_base
    __attribute__((used, section("__param"), aligned(sizeof(void *)))) = {
    param_name_base, 0, 0, param_set_ulong, param_get_ulong, { (void *)&wlan_base }
};
static struct kernel_param __param_wlan_size
    __attribute__((used, section("__param"), aligned(sizeof(void *)))) = {
    param_name_size, 0, 0, param_set_ulong, param_get_ulong, { (void *)&wlan_size }
};

/* ---- PPC instruction-stream flush ---------------------------------------- *
 * Write the modified word back through the data cache and invalidate it in the
 * instruction cache: dcbst; sync; icbi; isync.
 */
void wlanpatch_flush(volatile u32 *p)
{
    __asm__ __volatile__(
        "dcbst 0,%0\n\t"
        "sync\n\t"
        "icbi 0,%0\n\t"
        "isync\n\t"
        :: "r"(p) : "memory");
}

/* ---- rule: mcs-htcap, window A (func 0x208) ------------------------------ *
 * Relocation-free window covering the 2-stream site (ori 0x10 at +16) and the
 * Rx!=Tx site (ori 0x40 at +36). The ori immediate low byte of each (indices
 * 19 and 39) is masked so the window matches whether stock or patched.
 */
static const u8 sig_mcs_a[48] = {
    0x41,0x9e,0x00,0x0c, 0x2f,0x83,0x00,0x03, 0x41,0x9e,0x02,0x18,
    0x88,0x1f,0x00,0x0f, 0x60,0x00,0x00,0x10, 0x98,0x1f,0x00,0x0f,
    0x7f,0x9c,0x18,0x00, 0x41,0x9e,0x00,0x10, 0x88,0x1f,0x00,0x0f,
    0x60,0x00,0x00,0x40, 0x98,0x1f,0x00,0x0f, 0x38,0x00,0x00,0x00,
};
static const u8 msk_mcs_a[48] = {
    1,1,1,1, 1,1,1,1, 1,1,1,1,
    1,1,1,1, 1,1,1,0, 1,1,1,1,   /* index 19: ori 0x10 immediate */
    1,1,1,1, 1,1,1,1, 1,1,1,1,
    1,1,1,0, 1,1,1,1, 1,1,1,1,   /* index 39: ori 0x40 immediate */
};
static const struct edit edit_mcs_a[] = {
    { 16, 0x60000010u, 0x60000001u },   /* 2 Tx streams: Tx MCS Set Defined */
    { 36, 0x60000040u, 0x60000002u },   /* Rx != Tx: Tx Rx MCS Set Not Equal */
};

/* ---- rule: mcs-htcap, window B (func 0x420) ------------------------------ *
 * The 3-stream site (ori 0x20 at +12), bracketed by two intra-function
 * branches (relocation-free). The ori immediate byte (index 15) is masked.
 */
static const u8 sig_mcs_b[24] = {
    0x99,0x7f,0x00,0x05, 0x4b,0xff,0xfd,0xb8, 0x88,0x1f,0x00,0x0f,
    0x60,0x00,0x00,0x20, 0x98,0x1f,0x00,0x0f, 0x4b,0xff,0xfd,0xec,
};
static const u8 msk_mcs_b[24] = {
    1,1,1,1, 1,1,1,1, 1,1,1,1,
    1,1,1,0, 1,1,1,1, 1,1,1,1,   /* index 15: ori 0x20 immediate */
};
static const struct edit edit_mcs_b[] = {
    { 12, 0x60000020u, 0x60000001u },   /* 3 Tx streams: Tx MCS Set Defined */
};

static const struct rule rules[] = {
    { "mcs-htcap-a", sig_mcs_a, msk_mcs_a, sizeof(sig_mcs_a), edit_mcs_a, 2 },
    { "mcs-htcap-b", sig_mcs_b, msk_mcs_b, sizeof(sig_mcs_b), edit_mcs_b, 1 },
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
