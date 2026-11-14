# IBM OS/2 PACK2 / FT19

Native, bounded in-memory decoding of PACK2 members (signature A5 96 FD FF),
including stored payloads, FT19 two-stage compression, linked absolute member
offsets and separately compressed extended attributes. `auto` exposes original
paths and DOS metadata; `extended_attributes` retains raw FEA-list bytes.
It does not install those EAs into a target filesystem.

Input and individual output are limited to 256 MiB. `auto.Options` additionally
bounds entry count and cumulative file-plus-EA expansion. Invalid extents,
parent traversal, truncated streams and mismatched expanded sizes fail.
FT21 is explicitly unsupported. No external unpacker or intermediate file.

FT19 entropy ordering, bootstrap tables and token transforms are adapted from
Deark's MIT-licensed `src/fmtutil-ftcomp.c` and `foreign/ftcompdata.h`
(https://github.com/jsummers/deark). See LICENSE.deark for attribution.
Container framing was checked against `modules/os2pack.c` in the same project.
Tests use synthetic stored/FT19 chunks, overlapping LZ history, block boundaries,
truncation and malformed archive extents; original IBM media is not redistributed.
