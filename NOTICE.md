# Notices

## Licensing

This repository is dual-licensed by directory:

| Path | Licence | Why |
|---|---|---|
| `src/` (kernel modules) | **GPL-2.0-only** | The modules declare `MODULE_LICENSE("GPL")` and link Linux kernel symbols (some GPL-only), so they are derivative works of the kernel. |
| everything else (`scripts/`, `deploy/`, `docs/`, CI) | **MIT** | Standalone tooling and documentation. |

See [`LICENSE`](LICENSE) (MIT) and [`src/LICENSE`](src/LICENSE) (GPL-2.0-only).

## No vendor code is redistributed

These modules are original source. They ship **no** Ruckus or vendor binaries,
no vendor `wlan.ko`, and no vendor headers. The module's `struct module`,
`.modinfo` and vermagic are reconstructed in `wlan_fils.c` from the public
kernel ABI; the byte signatures in the rule tables are constants derived by
static analysis of drivers running on hardware the authors own. Nothing in this
repository contains or derives from Ruckus source code.

The modules patch a few instruction words of the **already-loaded** stock driver
in RAM at runtime. They do not modify, repackage or redistribute any firmware
image, and the on-flash driver is left untouched (a reboot restores stock).

## Affiliation

This project is not affiliated with or endorsed by Ruckus Networks, CommScope,
or any related entity. "Ruckus" and model names are used only to identify the
hardware the fixes apply to.

## Warranty

Running these modules writes to kernel memory on your access points. They are
provided without warranty of any kind. Use only on hardware you own, and read
the source — it is short — before loading anything.
