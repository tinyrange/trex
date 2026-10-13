# MIPS executable inspection

`binary.irix_executable(file)` reads MIPS ELF32/ELF64 and ECOFF32 images natively,
including big/little endian tables and MIPS1/MIPS3 ECOFF signatures. The result
exposes ABI/ISA flags, entry and GP, file-backed sections/segments, symbols,
relocations, dynamic tags, interpreter and needed library names.

ELF inspection preserves o32/n32/n64 distinctions. MIPS64 relocation records
retain their symbol, special-symbol byte, three operation types and signed RELA
addend. MIPS option and ABI-flag records are decoded, including 32/64-bit GP
fields. Stripped sectionless files can obtain dependencies through PT_DYNAMIC.
ECOFF symbolic headers are not mistaken for ordinary COFF symbol counts; local
names are resolved through file descriptors and external names through their
separate string table. Storage-class/type values and raw relocation bits remain
available.

Counts, entry sizes, string termination, table references, address/range
arithmetic and total record limits are checked. File-backed contents are
borrowed file views, not extracted files. NOBITS sections have no invented
source bytes.

This is structural executable/ABI inspection, **not** a MIPS interpreter,
dynamic loader, relocation applier, IRIX syscall implementation or full debug
information decoder. Sections whose payload formats are not interpreted remain
readable. Extended ELF symbol section indexes and other ECOFF generations are
explicit gaps.

Format facts follow primary [MIPS ELF declarations](https://github.com/torvalds/linux/blob/master/arch/mips/include/asm/elf.h),
the ELF gABI, and [ECOFF headers](https://github.com/NetBSD/src/blob/trunk/sys/sys/exec_ecoff.h).
The implementation is independent Go, not translated kernel/binutils code.
Synthetic ELF results are cross-checked against Go's independent `debug/elf`
reader. Original-media validation includes the 3.3 standalone ECOFF programs,
6.5.22's ECOFF/ELF standalone loaders and all 150 ELF files in its Overlay 1
miniroot. This does not establish runtime compatibility.
