# Amiga object-unit decoding

`OpenObjects` reads concatenated big-endian HUNK_UNIT objects without linking
or executing them. Raw unit/block views preserve all bytes. Names retain
longword padding; code/data/debug payloads and relocation tables are borrowed
files. BSS remains an allocation-size declaration, not extracted bytes.

The classic identifiers and external-symbol types are documented in Amiga's
[dos/doshunks.h](https://amigadev.elowar.com/read/ADCD_2.1/Includes_and_Autodocs_2._guide/node0065.html).
The layout is described in the AmigaDOS Technical Reference Manual, chapter2.
The implementation was developed from format facts and bounded Starlark
record probes, not a host loader or extractor.

`OpenLoad` additionally reads non-overlaid HUNK_HEADER modules and verifies
the allocation table against section counts and stored sizes. Header grammar
comes from the [AmigaDOS Technical Reference Manual, section2.3.1](https://manuals.plus/m/16a773db9b6197801ce9889f264dac01e535c27848ec0fcb9abdd4cf40711644).
Resident libraries remain names, not external reads. Allocation sizes do not
cause memory allocations. Extended memory attributes and compact load
relocations are not implemented.

EHF object records PPC_CODE (1257), RELRELOC26 (1260) and EXT_RELREF26 (229)
use the existing code, relocation-group and symbol-reference framing.
Their definitions come from Sam Jordan's 15-May-1997
[publisher specification](https://web.archive.org/web/20071116000000id_/http://www.haage-partner.de/amiga/storm/sc_tec_d.htm).
The relocation's 26-bit interpretation is preserved by its tag, not applied.

The reader rejects indexed libraries and overlays.
Those remain campaign work, not opaque successfully decoded
leaves. It checks framing and section order, but does not promise linker-level
validation of symbol values or relocation targets. All fixtures are synthetic.
