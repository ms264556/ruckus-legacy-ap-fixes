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

> The PowerPC module carries the empty `.plt` and `.init.plt` sections the
> 32-bit PowerPC module loader requires, and the build checks for them. On an
> R700 running 5.1.1.0.2150 (same kernel and module layout as 2.6) it loads,
> finds none of its patch sites, and unloads with ENODEV.

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

## URL filter agent stand-in

SmartZone 3.6.2 ships `avpd` with its web filter on every model, but the H500/C500
and ZF7372-family images leave out `uf_agent`, the daemon `avpd` asks for a
host's web category. `src/urlfilter/rmc-urlfilter.c` stands in for it: it
answers on `/tmp/urlfilter_evt.sock` in the 3.6 wire format and asks the
controller through the AP's SSH tunnel (`127.0.0.1:8082/rmc-category`).
`scripts/build-urlfilter.sh` builds `rmc-urlfilter-<arch>` with the same pinned
Zig and musl as iperf3. `rmc-urlfilter -q <host>` checks a running agent the way
`librsm` asks it. Proven on an H500 (3.6.2.0.759, MIPS).

With the controller's filter file (`src/urlfilter/rmc-filter.c`: a binary fuse
filter of every listed name, about 4.6 bytes a name) the agent answers by itself.
It fetches the file through the tunnel (`/rmc-filter`) every hour, keeps it in
`/writable/rmc-content-filter` when there is room, and when the controller has
been away for 2 days rebuilds it from the lists named in it, downloaded with
curl, in about 14 bytes of memory a name. `rmc-urlfilter -B <sources> -o <file>`
and `-L <file> <host>...` build and query a file off the AP; both builds of the
same lists are byte-identical apart from the header's time and origin. The
agent answers in each firmware's layout (3.6, 5.x, 6.x/7.x); proven on the H500
(3.6.2), R500 (5.2.2), R700 (5.1.1), R760 (7.1.1) and R560 (7.2).

Those images also run on small-memory models, and 3.6 `avpd` only turns its
DPI engine on (and with it the web filter) when `MemTotal` is above 200 000 kB:
`librsm`'s `rsm_mem_support_tm()`. `src/urlfilter/rmc-dpi-shim.c` is that one
function answering "supported", built as a libc-free `rmc-dpi-shim-<arch>.so`
and preloaded into `avpd` alone (`LD_PRELOAD=… /usr/sbin/avpd -i cif0 -D`).
The H500 (125 508 kB) then filters, with about 18 MB still free.

## RADIUS server for on-AP sign-ins

`scripts/build-radiusd.sh` builds `rmc-radiusd-<arch>`: hostapd 2.11's RADIUS and
EAP server (`driver=none`, no radio), statically linked against wolfSSL 5.7.6
(its hostapd profile, with MD4 and DES for MSCHAPv2) and musl with the same pinned
Zig. The build needs autoconf, automake and libtool for wolfSSL. An
AP runs it to check WPA2/WPA3-Enterprise usernames and passwords itself, so
sign-ins keep working while the controller is unreachable: PEAP/MSCHAPv2,
TTLS/PAP, TTLS/MSCHAPv2 and TTLS/EAP-MSCHAPv2. `src/radiusd/apply-patches.py`
changes three things in hostapd:

* phase-2 names match without a `DOMAIN\` prefix and ignoring ASCII case;
* TTLS/PAP is checked against a stored NT hash, so the users file holds no
  plaintext passwords;
* the server binds 127.0.0.2 only. SmartZone 2.x, 3.x and 5.1 send RADIUS over
  TCP when the server is exactly 127.0.0.1, and nothing off the AP can reach it.

| File | CPU | Size | Proven on |
|---|---|---|---|
| `rmc-radiusd-arm` | ARMv7 little-endian | 766 KB (384 KB `.gz`) | R560 (7.2), R760 (7.1.1) |
| `rmc-radiusd-mips` | MIPS32r2 big-endian | 1.12 MB (435 KB `.gz`) | R500 (5.2.2), H500 (3.6.2), ZF7372, ZF7962 (2.6) |
| `rmc-radiusd-ppc` | PowerPC 440 class, big-endian | 952 KB (445 KB `.gz`) | R700 (5.1.1) |

TLS 1.3 and ChaCha20/Poly1305 are left out (PEAP and TTLS run TLS 1.2 with AES), and each
`rmc-radiusd-<arch>.gz` is the binary gzipped with zopfli, for APs that keep it compressed on
flash and unpack it with `gunzip` or zlib's `minigzip`.

### Guest passes without the controller

`rmc-radiusd` has two more roles, chosen by its first argument (any other first
argument runs the RADIUS server as before). Both check a guest pass against a
pass list the controller writes to the AP, so guests keep signing in while the
controller is unreachable. Their sources are `src/radiusd/guest/`; they use
hostapd's own SHA-256 and HMAC, and nothing but libc otherwise.

```sh
rmc-radiusd guestd --passes <file> --bindings <file> --layout short|long \
                   --status run:<path>|int:<path> [--log <file>] [-B] [-P <pidfile>]
rmc-radiusd portal --passes <file> --bindings <file> --address <AP IP> \
                   [--terms] [--log <file>] [-B] [-P <pidfile>]
```

* **guestd** (SmartZone 3.6.2 to 7.x) puts itself in front of idm. authd sends
  every guest pass to idm's datagram socket `/var/run/idm`, and idm asks the
  controller. guestd hard-links idm's socket to `/var/run/idm.real`, binds its own
  socket and renames it over `/var/run/idm`. It passes every message on unchanged,
  descriptors included, from one relay socket per original sender. It answers a
  guest-pass request (id 5) itself only when the controller is unreachable: the
  status file says disconnected, the tunnel's 127.0.0.1:9081 refuses, or idm has
  not replied within 3 s. A late reply from idm is then dropped. When idm
  restarts, guestd takes the socket over again, and on SIGTERM it renames
  `/var/run/idm.real` back. `--layout short` is 3.6.2 to 5.2.2 (a 17-byte pass
  field); `long` is 6.1.2 and later. `--status run:<path>` counts as connected while
  the file reads `RUN` (3.6.2 `wsgclientState`); `int:<path>` counts as connected
  while the file holds a non-zero number (`.cubic_status`, `.cia_status`).
* **portal** (SCG 2.6, which has no AP-hosted guest portal) serves the WISPr
  hotspot's redirected HTTP on 8090. It redirects to its own form on 9997 with a
  signed ticket naming the device (from the `client_mac` header `wispr_http`
  adds, or from the ARP table). It checks the pass and authorises the station
  with hostapd's control command `AUTH mac <mac> proxy 0 u:<uuid> s:<seconds>
  uk:<uuid>`, sent to each socket in `/var/run/hostapd` until one answers `OK`.
  With `--terms`, the form is an accept button instead.

Both stay in the foreground unless given `-B`, and log to stderr (syslog when
detached) unless given `--log`. Each checks the pass list's file every second
and reloads it when it changes; SIGHUP reloads it at once. Every pass accepted
without the controller appends one line to the bindings file
(`<unix seconds> <uuid> <mac> first|device`), opening and closing the file for
each line, so the controller can collect it by renaming it away. The checks
match the controller's: the code with spaces and dashes dropped, revocation,
expiry, the device limit, 10 attempts per device per 5 minutes and 30 a minute
per AP. Every pass is refused while the AP's clock is earlier than the list's
own timestamp. Neither role has run on an AP yet. `tests/guest/run.sh` tests both roles with stand-ins for idm,
authd, the controller's port and hostapd, on the build host or under qemu
(`tests/guest/run.sh qemu-mips out/radiusd/rmc-radiusd-mips`).

wolfSSL is GPL-2.0-or-later, so each `rmc-radiusd-<arch>` is too, as a whole. The
script downloads the pinned hostapd and wolfSSL releases, removes every file the
build does not compile (other platforms, assembly, tests, unused C files; every
header and build file stays), packs the result with its own script and patches as
`rmc-radiusd-src.tar.xz` (about 2.7 MB), and then builds from exactly those trees,
so the archive is complete corresponding source by construction. The builds are
byte-for-byte reproducible.

## Licences

Kernel-module sources under `src/` are **GPL-2.0-only**; the build scripts,
`deploy/` scripts and docs are **MIT**. No vendor firmware or code is
redistributed. The `iperf3-<arch>` release files are built from upstream
iperf3 (BSD-3-Clause) and musl (MIT); their licences ship beside them as
`LICENSE.iperf3` and `COPYRIGHT.musl`. `src/urlfilter` (a userspace tool, not a
module) is MIT, like the scripts; its builds link musl. `src/radiusd` (a patch
script, a build configuration and the guest-pass roles) and `tests/` are MIT too; the `rmc-radiusd-<arch>` files are
hostapd (BSD-3-Clause) linked with wolfSSL (GPL-2.0-or-later) and musl, so they
are GPL-2.0-or-later; their licences ship beside them as `COPYING.hostapd` and
`COPYING.wolfssl`, and their source as `rmc-radiusd-src.tar.xz`. See
[`NOTICE.md`](NOTICE.md).

This project is not affiliated with or endorsed by Ruckus Networks or CommScope.
