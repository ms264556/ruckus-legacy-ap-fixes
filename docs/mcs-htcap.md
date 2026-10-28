# mcs-htcap: the HT Capabilities Tx MCS Set bug

## Symptom

A 2.6-era 11n Ruckus AP (e.g. ZF7962 on SCG 2.6) cannot mesh to a modern 7.x
root (e.g. R560 on 7.2): the root rejects the association with "Rx MCS set
mismatch". The same AP meshes fine to a 5.2.2 root, which does not perform the
offending check.

## Cause

In the 2.6 Atheros driver (`wlan.ko`, MIPS32r2 big-endian, Linux 2.6.32.24),
`ieee80211_add_htcap()` builds the HT Capabilities element. The **Supported MCS
Set** field is 16 bytes; byte 12 is the *Tx MCS Set parameters* byte, whose
802.11n layout is:

| bit | meaning |
|---|---|
| 0 | Tx MCS Set Defined |
| 1 | Tx Rx MCS Set Not Equal |
| 2-3 | Tx Maximum Number of Spatial Streams Supported |
| 4 | Tx Unequal Modulation Supported |
| 5-7 | reserved |

The driver uses the **wrong bits** for the Tx stream count and the not-equal
flag, and **never sets bit 0** (Tx MCS Set Defined). Every path therefore emits
a byte with reserved/unequal bits set while "defined" is clear — which 802.11n
forbids, and which the 7.x parser rejects. There is no setting that disables the
check; it is a defect in the transmitted element.

The driver writes byte 12 (`15(s0)` in the function frame) at three sites, one
per Tx-stream path:

```
# 2 Tx streams
1cc: lbu v0,15(s0) ; 1d0: ori v0,v0,0x10 ; 1d4: sb v0,15(s0)
# Rx != Tx
1e0: lbu v0,15(s0) ; 1e4: ori v0,v0,0x40 ; 1e8: sb v0,15(s0)
# 3 Tx streams (store is in the delay slot of a jump)
428: lbu v0,15(s0) ; 42c: ori v0,v0,0x20 ; 430: j 1d8 ; 434: sb v0,15(s0)
```

`0x10` = bit 4, `0x20` = bit 5, `0x40` = bit 6 — none of which is a correct
encoding of "2/3 Tx streams" or "not equal", and none sets bit 0.

## Fix

Rewrite each `ori` immediate so the byte becomes standards-conformant and
advertises the real Tx capability:

| site | stock | patched | result (byte 12) |
|---|---|---|---|
| 2 streams | `ori 0x10` (`0x34420010`) | `ori 0x01` (`0x34420001`) | Tx MCS Set Defined |
| 3 streams | `ori 0x20` (`0x34420020`) | `ori 0x01` (`0x34420001`) | Tx MCS Set Defined |
| Rx != Tx | `ori 0x40` (`0x34420040`) | `ori 0x02` (`0x34420002`) | Tx Rx MCS Set Not Equal (bit 1) |

The Tx Maximum Number of Spatial Streams field (bits 2-3) is reserved and must
be 0 unless *Tx Rx MCS Set Not Equal* is set, so a symmetric radio advertises
only *Tx MCS Set Defined* (0x01). v0.1.0 wrote 0x05 / 0x09 (Defined plus the
stream count) and the 7.x parser still refused it: its `ieee80211_parse_htcap`
accepts Defined=1 only when Not Equal is set or bits 2-4 are all clear. v0.1.1
writes 0x01, which a ZF7962 (2.6.0.0.388) was seen joining an R560 (7.2) with.

These combine correctly at runtime (2-stream + not-equal → `0x01 | 0x02 = 0x03`,
Defined and Not Equal with the stream field left for the Tx MCS bitmap). A 1×1 AP hits none of the stream ORs and (Rx == Tx) skips the not-equal
OR, so byte 12 stays `0x00` — already conformant.

The patcher locates each site by a byte signature (see `src/mips/wlanpatch.c`):
a relocation-free window covers the 2-stream and not-equal sites together; the
3-stream site has its store in a jump's delay slot, so its window masks the two
R_MIPS_26 jump words. The immediate byte of each `ori` is masked in the
signature so the site is still found after patching, which lets `rmmod` revert
it. (`ori v0,v0,0x10/0x20/0x40` on its own is extremely common in the driver —
12/10/12 occurrences — so the signature must match the full `lbu 15(s0)` / `ori`
/ `sb 15(s0)` bracket, not the bare `ori`.)

## Scope

Confirmed on MIPS 2.6.32.24 (ZF7962) and **PowerPC** 2.6.32.24 (ZF7982): both
`ieee80211_add_htcap` builds write MCS-set byte 12 with the same wrong bits at
the same three sites (load `0xf(frame)` / `ori 0x10|0x20|0x40` / store). The
2.6.0.0.388 and 2.6.0.0.370 ZF7962 functions are byte-identical, so the MIPS
signatures cover the shipping 388 build. The PowerPC rule (`src/ppc/`, planned)
uses the PPC `ori` encoding (`0x60000010` etc.) and a `dcbst`/`icbi` flush.

The newer ARM 3.14.43 driver encodes byte 12 correctly (no `orr #0x10/0x20/0x40`
into the Tx MCS byte), so there is no MCS rule for ARM.
