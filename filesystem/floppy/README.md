# Legacy floppy images

These readers expose logical 512-byte sectors directly from `storage.Reader`.
No host conversion, extraction, mounting, or temporary disk image is involved.

| Format | Go constructor | Starlark API |
| --- | --- | --- |
| DiskDupe DDI | `OpenDiskDupe` | `filesystem.diskdupe(file)` |
| HD-Copy, standard and extended | `OpenHDCopy` | `filesystem.hdcopy(file)` |
| The Duplicator, version 1 | `OpenDuplicator` | `filesystem.duplicator(file)` |

The returned read-only file can be passed to `filesystem.fat`. Automatic
browsing recognizes the wrappers and transparently enters supported contained
filesystems; unrecognized disk contents remain available as `disk.img`.
Original wrapper bytes remain accessible on the original node.

## Integrity and missing data

DiskDupe supports PC disk types 1–4 (360 KiB, 1.2 MB, 720 KiB, 1.44 MB).
The track map begins at decimal offset 100; stored track numbers address
track-sized units. Maps and stored ranges are checked, including overlap.

HD-Copy supports the standard 164-entry map and extended 168-entry map.
Every present track is decoded and its exact output length checked when opened.
Escape runs cannot overrun either their compressed block or logical track.
Decoded tracks use bounded in-memory buffers (at most 84 cylinders, two heads,
40 sectors per track); uncompressed formats borrow source ranges instead.

Omitted DiskDupe and HD-Copy tracks have **unknown contents**. Reads return
`ErrMissingTrack`, including a partial byte count when a request crosses from
recorded into missing data. Automatic identification uses only the contiguous
recorded prefix; actual filesystem reads still fail if required data is absent.

The Duplicator explicitly specifies a filler byte for unrecorded cylinders;
only those cylinders are synthesized. Version 1 cylinder checksums are **not
verified**. Automatic metadata reports `checksums_verified: false`.

Metadata includes geometry, logical size, omitted/filled unit counts, and unit
size. A unit is a track for DiskDupe/HD-Copy and a cylinder for The Duplicator.

Raw FAT images with trimmed unused tails need no wrapper: the existing FAT
reader can browse and read allocated content when all required bytes exist.
This does not reconstruct the original free-space bytes. A damaged image
without a valid header/map is not repaired by guessing from embedded sectors.
