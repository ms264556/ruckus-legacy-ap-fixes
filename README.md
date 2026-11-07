# ruckus-legacy-ap-fixes

Runtime bug fixes for discontinued Ruckus access points, built as small
loadable kernel modules that patch a few instruction words of the **already
loaded** stock `wlan.ko` in RAM. The on-flash firmware is never modified; a
reboot restores the stock driver. Every binary is built by GitHub Actions from
the sources here and carries a signed build-provenance attestation.

## What it fixes

| Fix | Module | What it does |
|---|---|---|
| **mcs-htcap** | `wlanpatch-mips.ko`, `wlanpatch-ppc.ko` | The 2.6-era Atheros driver writes the Tx MCS Set parameters byte of the HT Capabilities element with the wrong bits and never sets *Tx MCS Set Defined*, so a 7.x root rejects the association with "Rx MCS set mismatch". Corrects all three Tx-stream sites so old APs can mesh to a modern root. See [docs/mcs-htcap.md](docs/mcs-htcap.md). |
| **mesh-vlan-rx** | `wlanpatch-mips.ko`, `wlanpatch-arm.ko` | The mesh RX path runs a destructive VLAN inner-EtherType block (`memmove`/`skb_pull`) that corrupts mesh frames. Turns the conditional branch into an unconditional one. Found by Dan Brown ([`dbro/zd1200`](https://github.com/dbro/zd1200)). See [docs/mesh-vlan-rx.md](docs/mesh-vlan-rx.md). |

Each module carries **every rule for its architecture** and applies only the
ones whose site is present in the loaded driver — so one `insmod` fixes whatever
that AP actually has, and is a clean no-op for anything it doesn't.

## Supported architectures

| Target | Kernel | Module | Fixes present |
|---|---|---|---|
| MIPS32r2, big-endian | 2.6.32.24 | `wlanpatch-mips.ko` | mcs-htcap, mesh-vlan-rx |
| PowerPC, big-endian | 2.6.32.24 | `wlanpatch-ppc.ko` | mcs-htcap |
| ARMv7, little-endian | 3.14.43 | `wlanpatch-arm.ko` | mesh-vlan-rx (the ARM driver does not carry the MCS bug) |

> The 2.6.0.0.388 release spans two AP architectures: MIPS big-endian (most
> families) and PowerPC (the R700 / SC8800 / ZF7982 family). The PowerPC
> `ieee80211_add_htcap` carries the **identical** MCS bug, so `src/ppc/` applies
> the same three rewrites, with PPC `ori` encoding (`0x60000010`→`0x60000005`…)
> and a `dcbst`/`icbi` cache flush. Signatures are verified against the shipping
> 388 builds (the 388 ZF7962 function is byte-identical to the 370 image first
> analysed).

Adding a target is: a `src/<arch>/` directory and one `scripts/build.sh` arm in
the workflow. The build is a cross-compile with a stock Debian toolchain, so no
vendor build tree or SDK is needed.

## Getting the binaries

Every push and tag is built by CI. Each file has a SHA-256 in `SHA256SUMS` and a
signed build-provenance attestation tying it to the exact commit and workflow
run:

```bash
gh attestation verify wlanpatch-mips.ko --repo ms264556/ruckus-legacy-ap-fixes
sha256sum -c SHA256SUMS
```

Because the build is a deterministic cross-compile (`SOURCE_DATE_EPOCH` pinned,
Ubuntu 24.04 toolchain), a local rebuild with the same toolchain reproduces the
same bytes. And the whole patcher is ~150 lines of readable C that only rewrites
a named list of instruction words — you can confirm its scope by eye.

## Building

Linux with a stock cross toolchain:

```bash
sudo apt install gcc-mips-linux-gnu binutils-mips-linux-gnu \
                 gcc-powerpc-linux-gnu binutils-powerpc-linux-gnu \
                 gcc-arm-linux-gnueabi binutils-arm-linux-gnueabi python3

ARCH=mips ./scripts/build.sh      # -> out/mips/wlanpatch-mips.ko
ARCH=ppc  ./scripts/build.sh      # -> out/ppc/wlanpatch-ppc.ko
ARCH=arm  ./scripts/build.sh      # -> out/arm/wlanpatch-arm.ko
./scripts/package.sh              # -> dist/<arch>/ bundles + dist/SHA256SUMS
```

## Installing on an AP

Needs a root shell on the AP. Copy a `dist/<arch>/` bundle (the module,
`hook.sh`, `manifest.env`) to `/writable/ruckus-ap-fixes/`, which persists
across reboots and firmware upgrades, then:

```sh
cd /writable/ruckus-ap-fixes
cp hook.sh /writable/data/scripts/start/00-ruckus-ap-fixes   # re-applies each boot
base=$(awk '/^wlan /{print $6}' /proc/modules)
size=$(awk '/^wlan /{print $2}' /proc/modules)
insmod ./wlanpatch-*.ko wlan_base=$base wlan_size=$size      # or just run hook.sh
```

`hook.sh` checks the kernel version and module hash, passes the live `wlan`
base/size, and confirms the module stayed loaded. Getting the bundle onto the AP
is out of scope for this repo — copy it there however your setup allows (manual
`scp`, a controller, or a ZoneDirector); the hook handles the on-AP side.

To revert without a reboot: `rmmod wlanpatch` (reverts the sites whose signature
still matches; a reboot always restores the fully stock driver).

## Static iperf3 for speed tests

SmartZone 7.x firmware ships iperf3; 2.6 to 6.1 do not, and have no `nc` or
`httpd` either. `scripts/build-iperf3.sh` builds a static `iperf3-<arch>` per
CPU family from the upstream iperf 3.21 release, linked against musl with Zig
0.14.1 (both pinned by SHA-256), soft-float and without OpenSSL. glibc's static
binaries refuse the 2.6.32 kernels, so musl it is. A controller copies the
right one into the AP's `/tmp` (RAM) for an AP-to-AP speed test and deletes it
afterwards; nothing is installed.

| File | CPU | Runs on (live 2026-11-07) |
|---|---|---|
| `iperf3-mips` | MIPS32r2 big-endian | ZF7962, ZF7372 (2.6), H500 (3.6.2), R500 (5.2.2) |
| `iperf3-ppc` | PowerPC 440 class, big-endian (`-mcpu=440-isel`: no `lwsync`, no `isel`) | R700 (5.1.1) |
| `iperf3-arm` | ARMv7 little-endian | R560 (7.2, 32-bit userland); 3.6 to 6.1 ARM APs not yet tried |

The first PowerPC build used `lwsync` and died with "Illegal instruction" on the
R700's 4xx core; the 440 model alone still emits `isel`, which the core lacks
too.

## Licences

Kernel-module sources under `src/` are **GPL-2.0-only**; the build scripts,
`deploy/` scripts and docs are **MIT**. No vendor firmware or code is
redistributed. The `iperf3-<arch>` release files are built from upstream
iperf3 (BSD-3-Clause) and musl (MIT); their licences ship beside them as
`LICENSE.iperf3` and `COPYRIGHT.musl`. See [`NOTICE.md`](NOTICE.md).

This project is not affiliated with or endorsed by Ruckus Networks or CommScope.
