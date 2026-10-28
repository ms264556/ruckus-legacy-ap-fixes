/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * wlanpatch.c (MIPS) - runtime wlan.ko patcher for 2.6.32.24 MIPS32r2 APs.
 *
 * Carries two fixes and applies whichever is present in the loaded driver:
 *
 *   mesh-vlan-rx  The mesh RX VLAN inner-EtherType bypass (bnel -> b), the
 *                 scorpion fix found by Dan Brown (dbro/zd1200).  Absent on
 *                 builds that lack the destructive block (clean no-op).
 *
 *   mcs-htcap     ieee80211_add_htcap() writes the Tx MCS Set parameters byte
 *                 (MCS-set byte 12) with the wrong bits and never sets "Tx MCS
 *                 Set Defined", so a 7.x root rejects the association with
 *                 "Rx MCS set mismatch".  Three sites, one per Tx-stream path:
 *                   2 streams  ori 0x10 -> 0x05  (defined + 2 Tx streams)
 *                   3 streams  ori 0x20 -> 0x09  (defined + 3 Tx streams)
 *                   Rx != Tx   ori 0x40 -> 0x02  (Tx Rx MCS Set Not Equal)
 *
 * wlan base and size are module parameters supplied from /proc/modules:
 *
 *   insmod wlanpatch-mips.ko wlan_base=0x... wlan_size=...
 *
 * No <linux/module.h>: the 2.6.32 struct kernel_param layout is declared here
 * and wlan_fils.c supplies struct module, .modinfo and the vermagic.
 */
#include "../common/patch_engine.h"

/* ---- 2.6.32 module parameters -------------------------------------------- */

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

/* ---- MIPS instruction-stream flush --------------------------------------- */

void wlanpatch_flush(volatile u32 *p)
{
    __asm__ __volatile__("synci 0(%0)" :: "r"(p) : "memory");
}

/* ---- rule: mesh-vlan-rx -------------------------------------------------- */
/*
 * 64-byte signature of the catalog rule ap_11n_scorpion_mesh_vlan_rx.  The
 * branch displacement (bytes 22-23) and two relocated HI16/LO16 halves (34-35,
 * 42-43) are masked; the exact stock word 0x5462000b is verified at the edit.
 * This rewrite changes three bytes of the word, so the signature no longer
 * matches afterwards: rmmod cannot revert it, a reboot reloads stock.
 */
static const u8 sig_mesh[64] = {
    0x90,0x42,0x00,0x0c, 0x90,0x63,0x00,0x0d,
    0x00,0x02,0x12,0x00, 0x00,0x62,0x18,0x25,
    0x34,0x02,0x81,0x00, 0x54,0x62,0x00,0x00,
    0x8e,0xa2,0x01,0x08, 0x8e,0xa5,0x01,0x08,
    0x3c,0x02,0x00,0x00, 0x24,0x06,0x00,0x10,
    0x24,0x42,0x00,0x00, 0x00,0x40,0xf8,0x09,
    0x24,0xa4,0x00,0x02, 0x24,0x05,0x00,0x02,
    0x02,0x00,0xf8,0x09, 0x02,0xa0,0x20,0x21,
};
static const u8 msk_mesh[64] = {
    1,1,1,1, 1,1,1,1,
    1,1,1,1, 1,1,1,1,
    1,1,1,1, 1,1,0,0,
    1,1,1,1, 1,1,1,1,
    1,1,0,0, 1,1,1,1,
    1,1,0,0, 1,1,1,1,
    1,1,1,1, 1,1,1,1,
    1,1,1,1, 1,1,1,1,
};
static const struct edit edit_mesh[] = {
    { 20, 0x5462000bu, 0x1000000bu },   /* bnel -> b */
};

/* ---- rule: mcs-htcap, window A (0x1b0) ----------------------------------- */
/*
 * Relocation-free window covering the 2-stream site (ori 0x10 at +32) and the
 * Rx!=Tx site (ori 0x40 at +52).  The immediate low byte of each ori (indices
 * 35, 55) is masked so the window matches whether stock or patched, making the
 * edits revertible on rmmod.
 */
static const u8 sig_mcs_a[64] = {
    0x2c,0x42,0x00,0x02, 0x14,0x40,0x00,0x08,
    0x24,0x02,0x00,0x02, 0x10,0x62,0x00,0x03,
    0x24,0x02,0x00,0x03, 0x10,0x62,0x00,0x98,
    0x00,0x00,0x00,0x00, 0x92,0x02,0x00,0x0f,
    0x34,0x42,0x00,0x10, 0xa2,0x02,0x00,0x0f,
    0x12,0x63,0x00,0x04, 0x00,0x00,0x00,0x00,
    0x92,0x02,0x00,0x0f, 0x34,0x42,0x00,0x40,
    0xa2,0x02,0x00,0x0f, 0xa2,0x00,0x00,0x13,
};
static const u8 msk_mcs_a[64] = {
    1,1,1,1, 1,1,1,1,
    1,1,1,1, 1,1,1,1,
    1,1,1,1, 1,1,1,1,
    1,1,1,1, 1,1,1,1,
    1,1,1,0, 1,1,1,1,   /* index 35: ori 0x10 immediate */
    1,1,1,1, 1,1,1,1,
    1,1,1,1, 1,1,1,0,   /* index 55: ori 0x40 immediate */
    1,1,1,1, 1,1,1,1,
};
static const struct edit edit_mcs_a[] = {
    { 32, 0x34420010u, 0x34420005u },   /* 2 Tx streams: defined + bits2-3=1 */
    { 52, 0x34420040u, 0x34420002u },   /* Rx != Tx: Tx Rx MCS Set Not Equal */
};

/* ---- rule: mcs-htcap, window B (0x428) ----------------------------------- */
/*
 * The 3-stream site (ori 0x20 at +8); its store sits in the delay slot of a
 * jump, so the window spans two R_MIPS_26 jumps (indices 12-15 and 24-27,
 * masked) and the ori immediate byte (index 11, masked for revert).
 */
static const u8 sig_mcs_b[28] = {
    0xa2,0x05,0x00,0x05, 0x92,0x02,0x00,0x0f,
    0x34,0x42,0x00,0x20, 0x08,0x00,0x00,0x76,
    0xa2,0x02,0x00,0x0f, 0x00,0x00,0x18,0x21,
    0x08,0x00,0x00,0x5b,
};
static const u8 msk_mcs_b[28] = {
    1,1,1,1, 1,1,1,1,
    1,1,1,0, 0,0,0,0,   /* index 11: ori 0x20 immediate; 12-15: j (reloc) */
    1,1,1,1, 1,1,1,1,
    0,0,0,0,            /* 24-27: j (reloc) */
};
static const struct edit edit_mcs_b[] = {
    { 8, 0x34420020u, 0x34420009u },    /* 3 Tx streams: defined + bits2-3=2 */
};

/* ---- rule table ---------------------------------------------------------- */

static const struct rule rules[] = {
    { "mesh-vlan-rx", sig_mesh,  msk_mesh,  sizeof(sig_mesh),  edit_mesh,  1 },
    { "mcs-htcap-a",  sig_mcs_a, msk_mcs_a, sizeof(sig_mcs_a), edit_mcs_a, 2 },
    { "mcs-htcap-b",  sig_mcs_b, msk_mcs_b, sizeof(sig_mcs_b), edit_mcs_b, 1 },
};
#define N_RULES (sizeof(rules) / sizeof(rules[0]))

int init_module(void)
{
    struct mp_tally t;

    if (!wlan_base || !wlan_size)
        return -22;                 /* -EINVAL: no wlan base/size supplied */

    mp_apply(rules, N_RULES, wlan_base, wlan_size, &t);
    printk("wlanpatch: matched=%d written=%d already=%d failed=%d\n",
           t.matched, t.written, t.already, t.failed);

    if (t.failed)
        return -5;                  /* -EIO: a write-back did not verify */
    if (!t.matched)
        return -19;                 /* -ENODEV: no known site in this wlan */
    return 0;
}

void cleanup_module(void)
{
    mp_revert(rules, N_RULES, wlan_base, wlan_size);
}
