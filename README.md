# plmn-lock-patch

*Kiswahili | [English](README.en.md)*

Huzima ukaguzi wa PLMN / operator-lock kwenye binary za **ARM64** kwa
kubadilisha matawi ya masharti (`b.eq`) kuwa matawi ya lazima (`b`).

## Inafanya nini

Programu za watengenezaji (k.m. "dialer" ya modem) wakati mwingine hulinda
operator lock kwa kuangalia kuwepo kwa file fulani:

```c
if (access("/path/to/plmn_lock_disable", 0) == 0)
    skip_the_lock();   /* file ipo -> hakuna lock */
```

Kwenye lugha ya assembly ya ARM64, ukaguzi huo unaonekana hivi:

```asm
adrp  x0, <page ya string ya njia>
add   x0, x0, <offset>     ; x0 = address ya string ya njia
bl    access               ; ita access(path)
cmp   w0, #0               ; je, imerudi 0?
b.eq  <target>             ; kama ndiyo, ruka code ya lock  <-- hapa tunapopatch
```

Script hii inatafuta kila ukaguzi wa aina hiyo unaohusiana na marker string
uliyopewa, kisha inabadilisha `b.eq` kuwa `b` kuelekea **target ileile**.
Kwa hiyo lock inarukwa kila mara; kila kitu kingine kwenye binary kinabaki
kama kilivyokuwa, na file inayozalishwa inabaki na **ukubwa uleule kabisa**
(patch ya ndani - hakuna kinachohama, hakuna kinachovunjika).

## Mahitaji

- Python 3.8+
- `capstone`

```bash
pip install -r requirements.txt
```

## Matumizi

```bash
# Patch, inaandika dialer.bin.patched
python3 patch_plmn_lock.py dialer.bin

# Chagua jina la output mwenyewe
python3 patch_plmn_lock.py dialer.bin -o dialer.patched

# Angalia tu - onyesha kingepatchiwa nini, usiandike chochote
python3 patch_plmn_lock.py dialer.bin --dry-run

# Tafuta marker string tofauti
python3 patch_plmn_lock.py fw.bin --string "/some/other/path" -o out.bin

# Strings nyingi kwa mpigo mmoja, pamoja na backup ya original
python3 patch_plmn_lock.py fw.bin --string /a --string /b -o out.bin --backup

# Verbose: onyesha pia kila mahali string inapotumika kwenye code
python3 patch_plmn_lock.py dialer.bin --dry-run --verbose
```

Mfano wa matokeo:

```
[*] reading dialer.bin (588568 bytes, md5 f66ebfebefaecbf87161405bea03be7f)
[+] string '/mnt/data/etc/tzcfg/plmn_lock_disable' @ file 0x... (vaddr 0x...)
[+] checks found: 2
    [1] b.eq @ 0x01151c -> target 0x011580   20030054 -> 19000014
    [2] b.eq @ 0x011624 -> target 0x01168c   40030054 -> 1a000014
[+] wrote dialer.bin.patched (588568 bytes - size unchanged, safe)
[+] md5: b45d867e7cf8c449178cc835a4a508ee
```

## Inafanyaje kazi

1. **Tafuta marker string** kwenye binary (k.m. njia ya file ya config).
2. **Tafuta xrefs**: vunja `.text` kwa capstone na tafuta kila jozi ya
   `adrp` + `add` inayopakia address ya string hiyo.
3. **Linganisha pattern** (`bl` / `cmp` / `b.eq`) mara tu baada ya kila xref.
4. **Andika upya** kila `b.eq` kuwa `b` yenye target ileile (encoding ya
   ARM64: `0x54…` → `0x14…`, umbali unabaki uleule), thibitisha ukubwa wa
   file haujabadilika, kisha andika output. File ya ingizo haiguswi kamwe.

## Vikwazo

- **ARM64 (AArch64) pekee.** Decoder ya instructions ni mahsusi kwa ARM64;
  script inakataa binary zisizo ARM64 (ARMv7, MIPS, x86, ...).
- Ukaguzi lazima ufuate pattern ya `bl`/`cmp`/`b.cond` karibu na reference
  ya string. Firmware inayotekeleza lock kwa njia tofauti inahitaji mbinu
  tofauti - chunguza kwanza (`strings`, `od`, disassembly).
- Lazima ujue marker string moja (au orodha yake) kabla; tumia `--string`
  kuielekeza kwenye string sahihi ya kifaa chako.

## Usalama

- File ya ingizo **haiguswi kamwe**; file mpya ndiyo inaandikwa.
- Script **inakataa** kuandika juu ya ingizo lake (`-o` lazima iwe tofauti).
- Ukubwa wa output unathibitishwa kuwa sawa na wa ingizo kabla ya kuandika.
- `--dry-run` inaonyesha mabadiliko yote bila kuandika chochote.
- `--backup` inahifadhi nakala ya `<infile>.bak` ya original.
- Jaribu binary iliyopatchiwa kutoka mahali pa muda (k.m. `/tmp`) kila
  mara, na weka backup ya firmware/original kabla ya kugusa chochote
  cha kudumu.

## Kanusho

Kwa ajili ya utafiti, kujifunza, na majaribio yaliyoruhusiwa kwenye vifaa
unavyomiliki au umeruhusiwa kuvijaribu. Wewe unahusika na kufuata sheria
za nchi yako na masharti ya warranty ya kifaa chako.

## Leseni

MIT - tazama [LICENSE](LICENSE).
