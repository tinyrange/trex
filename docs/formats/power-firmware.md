# POWER firmware UI and LID framing

`archive/powerfirmware` reads the UI3 update container observed in IBM's
public POWER9 system firmware update bundles (FW930). Native gzip/tar
readers supply the bundle's `.img` file without host extraction. The UI
reader exposes borrowed `lids/ID/header.bin` and `payload.bin` views.

All integers below are big-endian. The 128-byte UI header has `UI` at 0,
version 3 at 2 (u16), exact image length at 4 (u32), directory offset at 12
(u16), and entry count at 14 (u16). The observed directory starts at 128 and
holds sixteen-byte records:

| Offset | Field |
| --- | --- |
| 0 | LID identifier, u32 |
| 4 | Total stored LID bytes, u32 |
| 8 | LID offset from UI start, u32 |
| 12 | Opaque checksum word, u32 |

LIDs begin with 0222/version 3 (two u16s), identifier at 4, the same checksum
word at 16, payload length at 20 and header length at 24 (all u32). The reader
requires at least 108 header bytes and an exact header-plus-payload extent;
extended headers are preserved. It rejects duplicate identifiers, directory
overlap, overlapping LIDs, out-of-bounds extents, mismatched identifiers or
checksum words, and entry/byte budget overruns before exposing the image.

Checksum agreement means header consistency only. The algorithm and coverage
are unestablished, so views explicitly report `checksum_verified=false`.
No signature trust, relocation, execution or complete interpretation of flags
is claimed. A version-1 marker LID carries the firmware level as a
length-prefixed keyword (`MIKeyword`).

## ISSI sector framing

`binary/issi` implements an 8×520 to 9×512 sector framing: a 4 KiB page of
eight 520-byte sectors (512 data bytes plus an 8-byte header each) is stored
as eight 512-byte data sectors and one 512-byte sidecar. Each data sector
keeps 504 bytes and replaces its final 8 bytes with a caller stamp; the
sidecar holds the displaced words and original headers:

| ISSI offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | Caller stamp |
| 8 | 64 | Eight original sector headers |
| 72 | 64 | Eight displaced sector-tail words |
| 136 | 64 | Received data-sector controls retained by decode flag 2 |
| 200 | 304 | Preserved reserved bytes |
| 504 | 8 | Caller stamp |

Encoding flags 1/2/4 save headers and tails, capture pointer tags, and stamp;
tag capture is subordinate to saving. Stamping requires a nonzero caller value;
it is not a checksum. Decoding restores the original tails and headers,
optionally retains the received controls at +136, and restores pointer tags.
Integrity checking is left to the consumer.

Pointer tags occupy 32 MSB-first bits per sector at sector header +3; header
byte 7 bit 0x08 marks their presence. Extraction changes a header only when
tags are nonzero. Ordinary stamp stores clear overlapping memory tags after
capture. The machine wrapper validates distinct bounded buffers before
mutation. Focused tests cover byte round trips, retained mismatching controls,
tag ordering, and invalid-input atomicity.
