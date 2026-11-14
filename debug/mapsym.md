# IBM/Microsoft MAPSYM symbols

`debug.mapsym(data)` reads a file or byte string and returns symbol records:
`module`, `segment_name`, `segment`, `name`, and `offset`.

These are unrelocated values. In particular, a kernel's segment ordinal/load
address is **not** its runtime selector. Obtain runtime object bases from the
matching executable/loader before resolving addresses. A segment load address
of zero is valid; absolute symbols have an empty segment name. Always use the
symbol file matching the executable build.

The native reader bounds paragraph pointers, relative symbol-table offsets,
names, counts and chains. It handles both 16-bit and 32-bit symbol offsets,
including circular final segment links. Input is capped at 1 MiB and decoded
symbols at one million. Version 4, 5 and 6 trailers are recognized; source line
tables and alphabetical indexes are not decoded.

Layout reference: Open Watcom `bld/watcom/h/mapsym.h` (IBM/Microsoft MAPSYM).
Only the format definitions were consulted; no implementation was copied.
Tests use synthetic records, not proprietary IBM symbols.
