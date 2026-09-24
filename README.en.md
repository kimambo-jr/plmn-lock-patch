# plmn-lock-patch

*English | [Kiswahili](README.md)*

Neutralize PLMN / operator-lock checks in **ARM64** binaries by rewriting
conditional branches (`b.eq`) as unconditional branches (`b`).

## What it does

Vendor daemons (for example a modem "dialer") sometimes guard an operator
lock behind a file check:

```c
if (access("/path/to/plmn_lock_disable", 0) == 0)
    skip_the_lock();   /* file exists -> no lock */
```

In ARM64 assembly that check looks like:

```asm
adrp  x0, <page of the path string>
add   x0, x0, <offset>     ; x0 = address of the path string
bl    access               ; call access(path)
cmp   w0, #0               ; did it return 0?
b.eq  <target>             ; if yes, jump over the lock code  <-- patched
```

This script finds every such check tied to a marker string and converts the
`b.eq` into a `b` to the **same** target. The lock is therefore always
skipped; everything else in the binary is untouched, and the output file
keeps the **exact same size** (in-place patching - nothing shifts).

## Requirements

- Python 3.8+
- `capstone`

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Patch, writing dialer.bin.patched
python3 patch_plmn_lock.py dialer.bin

# Choose the output name
python3 patch_plmn_lock.py dialer.bin -o dialer.patched

# Preview only - show what would be patched, write nothing
python3 patch_plmn_lock.py dialer.bin --dry-run

# Hunt for a different marker string
python3 patch_plmn_lock.py fw.bin --string "/some/other/path" -o out.bin

# Several marker strings at once, plus a backup of the original
python3 patch_plmn_lock.py fw.bin --string /a --string /b -o out.bin --backup

# Verbose: also list every place the string is referenced
python3 patch_plmn_lock.py dialer.bin --dry-run --verbose
```

Example output:

```
[*] reading dialer.bin (588568 bytes, md5 f66ebfebefaecbf87161405bea03be7f)
[+] string '/mnt/data/etc/tzcfg/plmn_lock_disable' @ file 0x... (vaddr 0x...)
[+] checks found: 2
    [1] b.eq @ 0x01151c -> target 0x011580   20030054 -> 19000014
    [2] b.eq @ 0x011624 -> target 0x01168c   40030054 -> 1a000014
[+] wrote dialer.bin.patched (588568 bytes - size unchanged, safe)
[+] md5: b45d867e7cf8c449178cc835a4a508ee
```

## How it works

1. **Find the marker string** in the binary (e.g. a config file path).
2. **Find xrefs**: disassemble `.text` with capstone and locate every
   `adrp` + `add` pair that loads the string's address.
3. **Match the check pattern** (`bl` / `cmp` / `b.eq`) right after each xref.
4. **Rewrite** each `b.eq` as `b` with the same target (ARM64 encoding:
   `0x54…` → `0x14…`, distance preserved), verify the file size is unchanged,
   and write the output. The input file is never modified.

## Limitations

- **ARM64 (AArch64) only.** The instruction decoder is ARM64-specific; the
  script refuses non-ARM64 binaries (ARMv7, MIPS, x86, ...).
- The check must follow the `bl`/`cmp`/`b.cond` pattern near a string
  reference. Firmware that implements the lock differently needs a
  different approach - analyze first (`strings`, `od`, disassembly).
- One marker string (or a list of them) must be known up front; use
  `--string` to point the tool at the right one for your target.

## Safety

- The input file is **never** modified; a new file is written.
- The script **refuses** to overwrite its own input (`-o` must differ).
- Output size is asserted equal to input size before writing.
- `--dry-run` previews every change without writing anything.
- `--backup` keeps a `<infile>.bak` copy of the original.
- Always test a patched binary from a scratch location (e.g. `/tmp`) and
  keep the original firmware/backups before touching anything persistent.

## Disclaimer

For research, learning, and authorized testing on devices you own or are
explicitly permitted to test. You are responsible for complying with local
laws and your device warranty terms.

## License

MIT - see [LICENSE](LICENSE).
