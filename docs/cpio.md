# Native CPIO package indexing

`archive.cpio(file, maximum_entries=100000, apple_double=False)` returns
flat Unix metadata records in archive order, with later duplicate paths replacing
earlier entries. The explicit entry ceiling counts input records, not fabricated
directories. Use a measured larger ceiling for large installer inventories;
limit errors identify the offending path and decoded offset.

The index uses a bounded 64 KiB sliding metadata window. Header/name/padding
reads are forward-only; large payloads are skipped, and returned file data stays
borrowed. CRC-newc checksums remain enforced. Regular-file hardlinks resolve
within each trailer-delimited archive; the `archive` field must be included
when preserving inode groups across concatenated archives.

With `apple_double=True`, macOS `._` entries are folded into their matching
file, directory or symlink metadata. FinderInfo is exactly 32 bytes; resource
forks and named attributes remain separate borrowed files. An extended entry 9
is not oversized FinderInfo: it contains the macOS ATTR header/table after two
alignment bytes. ATTR data offsets are absolute within the AppleDouble file.
Empty tables with allocated trailing space are valid. Unknown entry IDs,
missing targets and malformed metadata fail with the sidecar path.

Raw sidecars remain available with the default `apple_double=False`, and
`binary.appledouble` still returns unmodified entry-ID views.
`binary.appledouble_metadata` exposes decoded metadata and retains unknown IDs.
ATTR layout provenance: Apple's XNU 2050.48.11 `bsd/vfs/vfs_xattr.c`.

Retain compressed-package readers before metadata validation, and keep
successful parsed entries in the same media-owned cache. Indexed bzip2 readers
use a bounded decoded-block cache instead of keeping every expanded package in
RAM. Replaying gzip streams can use explicitly bounded paged RAM snapshots.
Metadata validation or later construction failures must not discard the shared
decoding/index prefix or trigger another complete inventory scan. No host extraction,
mounting or intermediary files are involved.
