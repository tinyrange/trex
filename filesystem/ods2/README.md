# Files-11 ODS-2 decoding

Initial primitives read a checksummed home block and decode a single file
header with format-1/2/3 retrieval pointers. File IDs retain the number, reuse
sequence and relative volume. Record attributes are retained separately from
the logical byte length; EOF and allocated-block fields have PDP-11 word order.

`ReadDirectory` reads bounded directory blocks and preserves all version/FID
pairs, including versions split across records. It checks counts, padding,
version ordering and IDs; unsupported flags fail explicitly.

`Open` bootstraps the index from its backup header and checks the primary
header through the mapped index. File-ID lookup uses index virtual blocks,
not physical adjacency. `Volume.File` returns a read-only extent-backed view,
checks allocation counts and logical EOF, and does not translate RMS records.
A fragmented-index fixture exercises the noncontiguous case explicitly.

`filesystem.ods2` exposes a bounded version-aware tree, exact-path lookup,
borrowed file data, raw headers and RMS attributes. The root self-reference is
preserved without recursion. Other cycles fail. File contents are not converted.

Extension-header chains remain unsupported. Retrieval format0 and other
structure versions fail explicitly. No mount,
guest program, host extractor or file-content conversion is involved.

Format references are DEC's *VMS File System Internals* (Kirby McCoy, 1990),
chapter2, and *VMS I/O User's Reference Manual, Part1* (1990), table1-9:

- [ODS-2 home blocks, file headers and retrieval maps](https://bitsavers.org/pdf/dec/vax/vms/training/EY-F575E-DP_VMS_File_System_Internals_1990.pdf)
- [Record attributes and inverted EOF fields](https://bitsavers.org/pdf/dec/vax/vms/5.4/AA-LA84B-TE_VMS_5.4_IO_Users_Reference_Manual_Part_1_199006.pdf)

The archived VMS5.5-2 and5.5-2H4 images have valid `DECFILE11B` home blocks
with structure0x0201 and cluster size1. Independent Starlark probes reach
their master directories via the index file; the roots occupy different
physical blocks and must not be located using a fixed data offset.
The H4 image additionally has Nero-style trailing metadata with inconsistent
stored offsets. Reading its ODS-2 blocks does not validate that outer layer.
Native trees match the independent Starlark catalogs:158 and169 entries
excluding the synthetic root. All151 and161 non-directory entries respectively
have been read and hashed. All312 logical sizes and SHA-256 hashes also match
independent Starlark extent reconstruction. This validates file access, not
nested savesets or record-format conversion.
All committed test fixtures are constructed, not copied from the media.
