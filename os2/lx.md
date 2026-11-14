# Read-only OS/2 LX inspection

`os2.linear_executable(source, maximum=64MiB)` accepts a file or bytes and
returns object and resource records. Object records expose `number`, `base`,
`flags`, and an unrelocated `file`. Resource records expose `type`, `id`,
`object`, `offset`, and a file containing the exact original resource bytes.

The decoder handles little-endian LX version 0 with 4096-byte pages, an
optional MZ stub, raw pages (0), iterated records (1), zero pages (3), and
EXEPACK2 pages (5). Invalid/range page types are rejected. File-relative page
offsets and header-relative tables are kept distinct. Short pages are
zero-padded. Resource references are bounded against decoded object sizes;
a resource may cross page boundaries. Neither relocations nor imports nor
initialization routines are applied or executed.

EXEPACK2 has four low-two-bit command tags: literal/run, short match with
literal prefix, short match, and long match with literal prefix. Matches
are copied byte-by-byte to support overlap; zero distances, underflow,
truncation and output overruns are errors. A zero/zero terminator ends a
short page. Both source and total object expansion are limited by the
Starlark API. Object/resource table counts have explicit allocation bounds.

Tests cover cross-page resources, MZ and direct LX, all compression tags,
overlap, zero padding, table/page/resource bounds and malformed streams.
The fuzz target exercises the parser and both page decoders together.
Original Warp 3 MMPM.DLL and CARDINFO.DLL exercise the implementation with
207 EXEPACK2 pages in MMPM and original multimedia device resources.

Format references: IBM LX object/page/resource table definitions; Ryan C.
Gordon's `icculus/2ine` lx_loader.c documents EXEPACK2's command bit fields
and points to LXlite 1.38u as the algorithm source. This implementation is
a bounded read-only Go parser, not the OS loader or its runtime environment.
