/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * patch_engine.h - architecture-independent runtime wlan.ko patcher core.
 *
 * A fix is a `rule`: a byte signature (with a mask for bytes that vary between
 * builds or relocate at load) that locates a window in the loaded wlan text,
 * plus one or more `edit`s that rewrite a 32-bit instruction word inside that
 * window.  Each edit verifies the stock word before writing and recognises the
 * patched word, so an already-patched or absent site is handled without harm.
 *
 * The signature bytes are stored in target memory order (big-endian words on
 * MIPS, little-endian on ARM); matching is a plain byte compare, so it is
 * endianness-agnostic.  The edit `stock`/`patched` values are the architectural
 * instruction words; the running CPU reads them in its own endianness, so a
 * native 32-bit compare/store is correct on each target.
 *
 * The module has no kernel headers: each architecture supplies wlan_base and
 * wlan_size as module parameters and a wlanpatch_flush() that pushes one
 * rewritten word back to the instruction stream.
 */
#ifndef PATCH_ENGINE_H
#define PATCH_ENGINE_H

typedef unsigned int u32;
typedef unsigned char u8;

struct edit {
    u32 off;        /* byte offset of the word within the matched window */
    u32 stock;      /* instruction word expected before patching         */
    u32 patched;    /* instruction word written in its place             */
};

struct rule {
    const char *name;
    const u8 *sig;
    const u8 *mask;     /* 1 = byte must match, 0 = ignore (varies/relocates) */
    u32 len;
    const struct edit *edits;
    u32 n_edits;
};

/* Architecture-provided: flush one rewritten instruction word at p. */
void wlanpatch_flush(volatile u32 *p);

struct mp_tally { int matched; int written; int already; int failed; };

/*
 * Scan [base, base+size) for exactly one masked match of r->sig.  Returns the
 * window base, or 0 when the rule is absent (no match) or ambiguous (>1).
 */
static const u8 *mp_find(const struct rule *r, const u8 *base, u32 size)
{
    u32 i, j, hits = 0;
    const u8 *hit = 0;

    if (!r->len || r->len > size)
        return 0;
    for (i = 0; i + r->len <= size; i++) {
        for (j = 0; j < r->len; j++)
            if (r->mask[j] && base[i + j] != r->sig[j])
                break;
        if (j == r->len) {
            if (++hits > 1)
                return 0;
            hit = base + i;
        }
    }
    return hits == 1 ? hit : 0;
}

/* Apply every rule that is present; leave absent/ambiguous/unexpected sites. */
static void mp_apply(const struct rule *rules, u32 n,
                     unsigned long base, unsigned long size,
                     struct mp_tally *t)
{
    u32 ri, ei;

    t->matched = t->written = t->already = t->failed = 0;
    if (!base || !size)
        return;
    for (ri = 0; ri < n; ri++) {
        const u8 *w = mp_find(&rules[ri], (const u8 *)base, (u32)size);
        if (!w)
            continue;
        t->matched++;
        for (ei = 0; ei < rules[ri].n_edits; ei++) {
            const struct edit *e = &rules[ri].edits[ei];
            volatile u32 *p = (volatile u32 *)(w + e->off);
            if (*p == e->patched) { t->already++; continue; }
            if (*p != e->stock)   { continue; }
            *p = e->patched;
            wlanpatch_flush(p);
            if (*p == e->patched) t->written++; else t->failed++;
        }
    }
}

/* Best-effort revert: only sites whose rule still matches post-patch. */
static void mp_revert(const struct rule *rules, u32 n,
                      unsigned long base, unsigned long size)
{
    u32 ri, ei;

    if (!base || !size)
        return;
    for (ri = 0; ri < n; ri++) {
        const u8 *w = mp_find(&rules[ri], (const u8 *)base, (u32)size);
        if (!w)
            continue;
        for (ei = 0; ei < rules[ri].n_edits; ei++) {
            const struct edit *e = &rules[ri].edits[ei];
            volatile u32 *p = (volatile u32 *)(w + e->off);
            if (*p == e->patched) {
                *p = e->stock;
                wlanpatch_flush(p);
            }
        }
    }
}

#endif /* PATCH_ENGINE_H */
