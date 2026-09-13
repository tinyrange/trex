# WIM 1.10

The legacy reader supports version `0x00010a00`, observed in original Windows
Fundamentals for Legacy PCs media. These notes describe byte-level observations,
not a claim to support every pre-release WIM revision. Compression uses the
existing native WIM chunk and LZX implementation. No external reader is used.

The 96-byte header contains the signature at 0, header size at 8, version at 12,
flags at 16 and chunk size at 20. Three 24-byte resource descriptors at offsets
24, 48 and 72 identify the lookup table, XML and boot metadata respectively.
Resource descriptor fields have the same encoding as later WIM generations.

Lookup records are 52 bytes: resource descriptor at 0, numeric stream ID at 24,
reference count at 28 and SHA-1 at 32. Metadata-flagged records enumerate images
in table order. This media leaves their hashes zero. File records refer to
numeric IDs, not hashes. ID zero denotes an empty unnamed stream, and must not
alias an unhashed image-metadata resource.

Image metadata starts with eight-byte security-descriptor length slots. The
first slot's upper DWORD contains the descriptor count; later upper DWORDs are
zero. The descriptors follow the slots, then eight-byte alignment. The root
is a list of named entries, with no synthetic empty-name root record. An empty
security table still occupies eight bytes.

Directory records have an aligned 64-bit length at 0, attributes at 8, security
ID at 12, directory child offset or file stream ID at 16, and three FILETIME
values at 24, 32 and 40. Stream count is a WORD at 56, short-name byte length at
58, long-name byte length at 60, and UTF-16LE long name at 62. A NUL follows each
name; the optional short name follows the long-name NUL. Zero length terminates
a directory list. Directory attributes, not nonzero child offsets, determine
whether an entry is a directory.

Additional stream records immediately follow their owning directory record.
They contain an aligned 64-bit length at 0, numeric stream ID at 8, a WORD name
byte length at 16, and a UTF-16LE name plus NUL at 18. An unnamed record selects
the main data stream; named records are retained as NTFS alternate data streams.

Synthetic tests cover nested directories, numeric references, short names,
timestamps, security lengths and bounds, alternate streams, missing resources,
and empty files alongside unhashed metadata. The NTFS builder has a separate
round-trip test for nonresident named stream bytes.

At the Starlark boundary, a WIM file's `streams` dictionary exposes named streams
as portable files. Applying an image to `directory()` preserves these streams
in filesystem metadata; the NTFS builder emits named `$DATA` attributes directly.
