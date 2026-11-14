# OS/2 FAT12/16 extended attributes

The FAT12/16 builders consume `directory.set_extended_attributes` metadata.
They serialize OS/2's hidden/system/read-only `EA DATA. SF` root file and put
per-object EA handles in short-directory-entry word 20. FAT32 still uses that
word for cluster numbers; this format is deliberately not used there.

The EA filename's extension begins with a significant space. Short-name
reading trims only right-side padding, preserving the exact name.

A 512-byte `ED` file header contains 240 base-cluster entries. 128-handle
offset tables follow; unused entries are `ffff`. A handle selects base
`handle >> 7` plus its offset entry. Each EA set is cluster-aligned, starts
with `EA` and its own handle, and stores required-EA count, DOS owner name,
reserved bytes, and a packed FEA list including its `cbList` length.
Opaque binary values and EA flags are preserved. Root-object EAs, collisions
with an existing EA store, unrepresentable handle/cluster counts and oversized
EA lists are rejected. The caller's directory is not mutated.

Primary layout references: Microsoft Windows-driver-samples,
`filesys/fastfat/fat.h` (`EA_FILE_HEADER`, `EA_SET_HEADER`, `PACKED_EA`) and
`filesys/fastfat/easup.c` (base/offset lookup and handle bounds). This is an
independent serializer based on those structures, not an adaptation of the
driver implementation.

Tests independently walk raw directory entries and the EA tables across
128-handle boundaries and multiple cluster geometries, including multi-cluster
values. The OS/2 recipe's EA smoke uses the original REXXUTIL `SysGetEA` and
`SysPutEA` implementations and checks a second cold boot.
