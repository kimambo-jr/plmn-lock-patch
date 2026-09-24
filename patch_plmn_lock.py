#!/usr/bin/env python3
"""
patch_plmn_lock.py
==================
Neutralize PLMN / operator-lock checks in an ARM64 binary.

What it does
------------
Vendor daemons (e.g. a modem "dialer") often guard a lock behind a file
check that looks like this in C:

    if (access("/path/to/plmn_lock_disable", 0) == 0)
        skip_the_lock();          // file exists -> no lock

In ARM64 assembly the check compiles to something like:

    adrp  x0, <page of the path string>
    add   x0, x0, <offset>        ; x0 = address of the path string
    bl    access                  ; call access(path)
    cmp   w0, #0                  ; did it return 0?
    b.eq  <target>               ; if yes, jump over the lock code

This script finds every such check tied to a given marker string and
rewrites the conditional branch ``b.eq`` as an unconditional ``b`` to the
*same* target. The lock is therefore always skipped, while everything else
in the binary stays untouched. The patched file keeps the exact same size
(in-place patching - nothing shifts, nothing breaks).

Method (the same one you can do by hand):
  1. Find the marker string inside the binary.
  2. Find code that loads the string's address (``adrp`` + ``add`` pairs).
     These are the "xrefs" - the places where the string is used.
  3. After each xref, match the ``bl`` / ``cmp`` / ``b.eq`` pattern.
  4. Replace ``b.eq`` with ``b`` (same target) and write a new file.

Requirements
------------
    pip install capstone        (or: pip install -r requirements.txt)

Usage
-----
    python3 patch_plmn_lock.py dialer.bin -o dialer.patched
    python3 patch_plmn_lock.py dialer.bin --dry-run
    python3 patch_plmn_lock.py fw.bin --string "/some/path" -o out.bin
    python3 patch_plmn_lock.py fw.bin --string /a --string /b -o out.bin --backup

Limitations
-----------
    * ARM64 (AArch64) binaries ONLY. The instruction decoder in this file is
      ARM64-specific; ARMv7, MIPS, x86 and other architectures are rejected.
    * The lock check must follow the bl/cmp/b.cond pattern near a string
      reference. Firmware that checks the lock differently needs a
      different approach.
    * For research and authorized testing on devices you own or are
      explicitly allowed to test. Test the patched binary from a scratch
      location (e.g. /tmp) before touching anything persistent.
"""

import argparse
import hashlib
import shutil
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
except ImportError:
    sys.exit("[!] The 'capstone' package is required.\n"
             "    Install it with:  pip install capstone")


# ---------------------------------------------------------------------------
# ARM64 instruction helpers
# ---------------------------------------------------------------------------
# A64 instructions are always 4 bytes, little-endian. The branch distance is
# stored *inside* the instruction as a count of instructions (x4 = bytes),
# relative to the branch instruction itself.
#
#   b.cond <target>   ->  0x54 | (imm19 << 5) | cond      (cond 0 = EQ)
#   b      <target>   ->  0x14 | imm26

def decode_bcond(word, addr):
    """Decode a b.cond instruction word -> (target_address, condition)."""
    imm19 = (word >> 5) & 0x7FFFF
    if imm19 & 0x40000:              # sign-extend negative distances
        imm19 -= 0x80000
    return addr + (imm19 << 2), word & 0xF


def encode_b(target, addr):
    """Build the 4 bytes of an unconditional 'b <target>' instruction."""
    imm26 = (target - addr) // 4
    if not -(2 ** 25) <= imm26 < 2 ** 25:
        raise ValueError(f"target 0x{target:x} too far from branch at 0x{addr:x}")
    return struct.pack("<I", 0x14000000 | (imm26 & 0x3FFFFFF))


def decode_adrp_target(word, addr):
    """Decode 'adrp xR, page' -> absolute address of the 4 KiB page."""
    imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    if imm & 0x100000:               # sign-extend
        imm -= 0x200000
    return (addr & ~0xFFF) + (imm << 12)


def decode_add_imm(word):
    """Decode 'add xR, xR, #imm' -> the immediate value."""
    imm12 = (word >> 10) & 0xFFF
    shift = (word >> 22) & 0x3
    return imm12 << (12 if shift == 1 else 0)


# ---------------------------------------------------------------------------
# ELF parsing: map CPU addresses <-> file offsets
# ---------------------------------------------------------------------------
def parse_elf_sections(data):
    """Return [{'name','addr','offset','size'}, ...] for an ELF64 file."""
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file (bad magic)")
    if data[4] != 2:
        raise ValueError("not a 64-bit ELF file")
    e_machine = struct.unpack_from("<H", data, 0x12)[0]
    if e_machine != 0xB7:            # 0xB7 = EM_AARCH64
        raise ValueError(
            f"not an AArch64 binary (e_machine=0x{e_machine:x}); "
            "this tool supports ARM64 only")

    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]   # section headers offset
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    s = e_shoff + e_shstrndx * e_shentsize
    str_off = struct.unpack_from("<Q", data, s + 24)[0]  # section-name strings

    sections = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        sh_name, _, _, sh_addr, sh_offset, sh_size = \
            struct.unpack_from("<IIQQQQ", data, o)
        end = data.index(b"\x00", str_off + sh_name)
        name = data[str_off + sh_name:end].decode()
        sections.append({"name": name, "addr": sh_addr,
                         "offset": sh_offset, "size": sh_size})
    return sections


def vaddr_to_offset(sections, vaddr):
    """CPU address -> file offset (None if not inside a known section)."""
    for s in sections:
        if s["addr"] <= vaddr < s["addr"] + s["size"]:
            return vaddr - s["addr"] + s["offset"]
    return None


def offset_to_vaddr(sections, off):
    """File offset -> CPU address (None if not inside a known section)."""
    for s in sections:
        if s["offset"] <= off < s["offset"] + s["size"]:
            return off - s["offset"] + s["addr"]
    return None


# ---------------------------------------------------------------------------
# Check hunting
# ---------------------------------------------------------------------------
def find_string(data, sections, marker):
    """Locate the marker string -> (file_offset, vaddr); (None, None) if absent."""
    off = bytes(data).find((marker + "\x00").encode())
    if off < 0:
        return None, None
    return off, offset_to_vaddr(sections, off)


def find_check_branches(data, sections, str_vaddr, verbose=False):
    """
    Disassemble .text and return [(branch_addr, target), ...] - one entry per
    lock check of the form:

        adrp xR, <page>      ; \
        add  xR, xR, #imm    ; / xR = address of our marker string
        bl   <func>          ;    e.g. access(path)
        cmp  w0, #0          ;    did it return 0?
        b.eq <target>        ;    if yes -> skip the lock   <-- we patch this
    """
    text = next((s for s in sections if s["name"] == ".text"), None)
    if text is None:
        raise ValueError("no .text section found")

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    code = bytes(data[text["offset"]:text["offset"] + text["size"]])
    insns = list(md.disasm(code, text["addr"]))

    found = []
    for i, ins in enumerate(insns):
        if ins.mnemonic != "adrp":
            continue
        # Does this adrp+add load OUR string's address?
        w = struct.unpack_from("<I", data, vaddr_to_offset(sections, ins.address))[0]
        page = decode_adrp_target(w, ins.address)
        nxt = insns[i + 1]
        if nxt.mnemonic != "add" or nxt.address != ins.address + 4:
            continue
        w2 = struct.unpack_from("<I", data, vaddr_to_offset(sections, nxt.address))[0]
        if page + decode_add_imm(w2) != str_vaddr:
            continue
        if verbose:
            print(f"    [v] xref: string loaded at 0x{ins.address:06x}")

        # Look for the bl / cmp / b.eq check right after the load.
        seen_cmp = False
        for j in range(i + 2, min(i + 10, len(insns))):
            cj = insns[j]
            if cj.mnemonic == "bl":
                continue
            if cj.mnemonic == "cmp":
                seen_cmp = True
                continue
            if cj.mnemonic == "b.eq" and seen_cmp:
                w3 = struct.unpack_from(
                    "<I", data, vaddr_to_offset(sections, cj.address))[0]
                target, cond = decode_bcond(w3, cj.address)
                if cond != 0:
                    break            # not EQ - not the pattern we know
                found.append((cj.address, target))
                break
            break                    # some other pattern - not our check
    return found


def apply_patches(data, sections, patches):
    """Rewrite each b.eq as b (same target). Returns list of change records."""
    changes = []
    for addr, target in patches:
        new_bytes = encode_b(target, addr)
        off = vaddr_to_offset(sections, addr)
        old_bytes = bytes(data[off:off + 4])
        data[off:off + 4] = new_bytes
        changes.append({"addr": addr, "target": target,
                        "old": old_bytes, "new": new_bytes})
    return changes


def md5_of(data):
    return hashlib.md5(bytes(data)).hexdigest()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser():
    ap = argparse.ArgumentParser(
        description="Neutralize lock checks in an ARM64 binary "
                    "(rewrite b.eq as b near a marker string).")
    ap.add_argument("infile", help="input binary (never modified)")
    ap.add_argument("-o", "--outfile", default=None,
                    help="output file (default: <infile>.patched)")
    ap.add_argument("--string", action="append", default=[],
                    help="marker string to hunt for (repeatable)")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be patched, write nothing")
    ap.add_argument("--backup", action="store_true",
                    help="keep a copy of the input as <infile>.bak first")
    ap.add_argument("--verbose", action="store_true",
                    help="also print every string reference found")
    return ap


def main():
    args = build_parser().parse_args()
    markers = args.string or ["/mnt/data/etc/tzcfg/plmn_lock_disable"]
    outfile = args.outfile or (args.infile + ".patched")

    if outfile == args.infile:
        sys.exit("[!] refusing to overwrite the input file; choose -o <other name>")

    try:
        data = bytearray(open(args.infile, "rb").read())
    except FileNotFoundError:
        sys.exit(f"[!] file not found: {args.infile}")
    orig_len = len(data)
    print(f"[*] reading {args.infile} ({orig_len} bytes, md5 {md5_of(data)})")

    if args.backup:
        bak = args.infile + ".bak"
        shutil.copyfile(args.infile, bak)
        print(f"[*] backup saved: {bak}")

    try:
        sections = parse_elf_sections(data)
    except ValueError as e:
        sys.exit(f"[!] {e}")

    # --- hunt every marker string ---
    patches = []
    for marker in markers:
        str_off, str_vaddr = find_string(data, sections, marker)
        if str_off is None:
            print(f"[!] string not found, skipping: {marker}")
            continue
        print(f"[+] string {marker!r} @ file 0x{str_off:x} (vaddr 0x{str_vaddr:x})")
        patches += find_check_branches(data, sections, str_vaddr,
                                       verbose=args.verbose)

    # de-duplicate (two markers could point at the same check)
    patches = sorted(set(patches))
    print(f"[+] checks found: {len(patches)}")
    if not patches:
        sys.exit("[!] nothing to patch - is --string right for this binary?")

    for n, (addr, target) in enumerate(patches, 1):
        new_bytes = encode_b(target, addr)
        off = vaddr_to_offset(sections, addr)
        old_bytes = bytes(data[off:off + 4])
        print(f"    [{n}] b.eq @ 0x{addr:06x} -> target 0x{target:06x}   "
              f"{old_bytes.hex()} -> {new_bytes.hex()}")

    if args.dry_run:
        print("[*] dry-run: nothing was written")
        return 0

    changes = apply_patches(data, sections, patches)
    assert len(data) == orig_len, "FATAL: file size changed during patching!"
    with open(outfile, "wb") as f:
        f.write(data)
    print(f"[+] wrote {outfile} ({len(data)} bytes - size unchanged, safe)")
    print(f"[+] md5: {md5_of(open(outfile,'rb').read())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
