#!/usr/bin/env python3
"""Finalise the `ld -r` output so the module owns its init/exit and name.

The wlan_fils.c stub supplies struct module, .modinfo and the vermagic. Rewrite
the init/exit relocations in .rel.gnu.linkonce.this_module to the patcher's
wlanpatch_init / wlanpatch_cleanup, and set "wlanpatch" in struct module's name
field (offset 0x0c). Endianness is read from the ELF header, so one script
serves both the big-endian MIPS and little-endian ARM objects.
"""

import struct
import sys

SYM = 16   # Elf32_Sym
REL = 8    # Elf32_Rel


def main(path: str) -> None:
    data = bytearray(open(path, "rb").read())
    if data[:4] != b"\x7fELF" or data[4] != 1:
        raise SystemExit(f"{path}: not an ELF32 object")
    en = "<" if data[5] == 1 else ">"      # EI_DATA: 1 = LE, 2 = BE

    e_shoff = struct.unpack_from(en + "I", data, 0x20)[0]
    e_shentsize = struct.unpack_from(en + "H", data, 0x2E)[0]
    e_shnum = struct.unpack_from(en + "H", data, 0x30)[0]
    e_shstrndx = struct.unpack_from(en + "H", data, 0x32)[0]

    def section(i):
        return struct.unpack_from(en + "IIIIIIIIII", data, e_shoff + i * e_shentsize)

    def cstr(base, off):
        end = data.index(b"\0", base + off)
        return data[base + off:end].decode()

    shstr = section(e_shstrndx)[4]
    names = {cstr(shstr, section(i)[0]): i for i in range(e_shnum)}

    if ".symtab" not in names:
        raise SystemExit(f"{path}: no .symtab")
    symtab = section(names[".symtab"])
    strtab = section(symtab[6])[4]

    symbols = []
    for i in range(symtab[5] // SYM):
        st_name = struct.unpack_from(en + "I", data, symtab[4] + i * SYM)[0]
        symbols.append(cstr(strtab, st_name))

    def sym_index(name):
        try:
            return symbols.index(name)
        except ValueError:
            raise SystemExit(f"{path}: symbol {name} not found")

    init_sym = sym_index("wlanpatch_init")
    cleanup_sym = sym_index("wlanpatch_cleanup")

    rel_name, stride = None, REL
    for cand, st in ((".rela.gnu.linkonce.this_module", 12),
                     (".rel.gnu.linkonce.this_module", REL)):
        if cand in names:
            rel_name, stride = cand, st
            break
    if rel_name is None:
        raise SystemExit(f"{path}: no .rel[a].gnu.linkonce.this_module")
    rel = section(names[rel_name])
    this_module = section(rel[7])          # sh_info -> target section

    # REL and RELA both carry r_info at entry offset +4 (RELA adds an addend
    # at +8 that we leave untouched), so one loop handles both.
    patched = 0
    for off in range(rel[4], rel[4] + rel[5], stride):
        r_info = struct.unpack_from(en + "I", data, off + 4)[0]
        sym, typ = r_info >> 8, r_info & 0xFF
        name = symbols[sym]
        new = None
        if "init" in name:
            new = init_sym
        elif "cleanup" in name or "exit" in name:
            new = cleanup_sym
        if new is not None:
            struct.pack_into(en + "I", data, off + 4, (new << 8) | typ)
            patched += 1
    if patched != 2:
        raise SystemExit(f"{path}: rewrote {patched} init/exit relocations, expected 2")

    name_off = this_module[4] + 0x0C
    data[name_off:name_off + 64] = b"wlanpatch\0" + b"\0" * 54

    with open(path, "wb") as fh:
        fh.write(data)
    print(f"finalised {path}: name=wlanpatch, {patched} relocations")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} MODULE.ko")
    main(sys.argv[1])
