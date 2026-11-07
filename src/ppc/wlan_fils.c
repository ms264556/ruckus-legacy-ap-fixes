/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * wlan_fils.c (PowerPC) - minimal 2.6.32 module stub, no vendor wlan_fils.ko.
 *
 * Layout read from the vendor PPC wlan.ko's .gnu.linkonce.this_module: state/
 * list at 0x00, name at 0x0c, init at 0xbc, exit at 0x138, total 0x148 bytes
 * (the exit pointer and size differ from the MIPS build). Only name/init/exit
 * are set; the loader fills the rest at load time. The same layout and
 * vermagic are in the R700 family's 2.6.0.0.388 and 5.1.1.0.2150 kernels
 * (their wlan_wep.ko).
 */
typedef unsigned int u32;

struct module_stub {
    u32 state;
    u32 list_next;
    u32 list_prev;
    char name[64];
    unsigned char pad0[0xbc - 0x0c - 64];
    int (*init)(void);
    unsigned char pad1[0x138 - 0xbc - 4];
    void (*exit)(void);
    unsigned char pad2[0x148 - 0x138 - 4];
} __attribute__((packed));

extern int wlanpatch_init(void);
extern void wlanpatch_cleanup(void);

/* Aligned like the stock modules' section (4): the struct is packed only to pin its offsets. */
struct module_stub __this_module
    __attribute__((section(".gnu.linkonce.this_module"), used, aligned(4))) = {
    .name = "wlanpatch",
    .init = wlanpatch_init,
    .exit = wlanpatch_cleanup,
};

static const char mod_license[] __attribute__((section(".modinfo"), used)) =
    "license=GPL";
static const char mod_depends[] __attribute__((section(".modinfo"), used)) =
    "depends=wlan";
static const char mod_vermagic[] __attribute__((section(".modinfo"), used)) =
    "vermagic=2.6.32.24 mod_unload ";

/*
 * The 32-bit PowerPC module loader (arch/powerpc/kernel/module_32.c,
 * module_frob_arch_sections) refuses a module without .plt and .init.plt
 * ("Module doesn't contain .plt or .init.plt sections.", insmod: invalid
 * module format) and sizes them itself for the trampolines of calls into the
 * kernel. A kernel tree's module build adds them; this one adds them here,
 * empty, NOBITS and 8-aligned like the stock modules'.
 */
__asm__(".section .plt,\"ax\",@nobits\n\t.p2align 3\n\t.previous\n"
        ".section .init.plt,\"ax\",@nobits\n\t.p2align 3\n\t.previous\n");
