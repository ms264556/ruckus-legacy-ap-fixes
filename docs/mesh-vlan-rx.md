# mesh-vlan-rx: the mesh RX VLAN inner-EtherType bug

## Credit

The bug and its fix were found by Dan Brown in
[`dbro/zd1200`](https://github.com/dbro/zd1200), which patches `wlan.ko` in the
AP firmware image (catalog rule `ap_11n_scorpion_mesh_vlan_rx`). This repository
applies the same change at runtime instead of rebuilding the firmware.

## Cause

In `ieee80211_input()`, the receive path checks the frame's inner EtherType for
`0x8100` (802.1Q VLAN) and then runs a block that shifts the payload:

```c
memmove(data + 2, data, 16);
skb_pull(skb, 2);
```

On the mesh RX path this is destructive and corrupts mesh frames. The fix turns
the conditional branch guarding the block into an unconditional branch, so the
block is always skipped.

## Fix

### MIPS (2.6.32.24)

The check tail ends in a `bnel` that is rewritten to an unconditional `b`:

| | value |
|---|---|
| stock | `0x5462000b` (`bnel`) |
| patched | `0x1000000b` (`b`) |

The 64-byte signature (catalog rule `ap_11n_scorpion_mesh_vlan_rx`) masks the
branch displacement and two relocated HI16/LO16 halves; the exact stock word is
verified before the write. This rewrite changes three bytes of the word, so the
signature no longer matches afterwards — `rmmod` cannot revert it and a reboot
reloads the stock driver.

### ARM (3.14.43)

The `ldrh`/`rev16`/`uxth`/`cmp #0x8100`/`bne` tail is identical across the
ZoneDirector 10.5.1.x and SmartZone 5.2.2 builds; only the first `ldr` differs
because `struct sk_buff` moved by 12 bytes, so two signatures are tried:

| build | first instruction |
|---|---|
| ZD 10.5.1.x | `ldr r3,[r4,#0x118]` (`0xe5943118`) |
| SZ 5.2.2 | `ldr r3,[r6,#0x124]` (`0xe5963124`) |

The `bne` at the end is rewritten to `b`:

| | value |
|---|---|
| stock | `0x1a000002` (`bne`) |
| patched | `0xea000002` (`b`) |

The `bne` condition byte is masked in the signature so the site is still found
after patching, allowing `rmmod` to revert it.

## Scope

Present on the MIPS "scorpion" and ARM 3.14.43 builds that carry the destructive
block. Builds without it (e.g. the SmartZone 5.2.2 MIPS scorpion image) produce
no signature match and the rule is a clean no-op.
