# VMS BACKUP decoding (in progress)

`ReadBlocks` (Starlark: `archive.vmsbackup_blocks`) reads a complete
single-volume block stream, validates both checksums and block sequences,
and exposes bounded record payload views. Each encountered redundancy payload
must equal the XOR of the preceding group's data payloads. Redundancy is not
required for a final group or a stream written without redundancy. No damaged
block is repaired. Limits bound block size, block count and total record count.

`ParseAttributes` reads version-1 summary/file attribute TLVs.
Values are byte-packed, not word-aligned. Unknown and duplicate attributes
remain present. `Files` (Starlark: `archive.vmsbackup`) joins file-data records
at consecutive virtual block addresses and exposes borrowed logical file views.
Names remain raw VMS names, not host paths; all attributes remain inspectable.
RMS record/index interpretation and volume/file-ID record interpretation remain
unfinished layers.

An entry with nonzero declared size but no stored payload has
`missing_contents=True` and `data=None`. This describes absence without guessing
its cause. It is distinct from an empty file, which has an empty data view.
Partly stored files and VBN gaps/overlaps are errors; no missing bytes are
filled in. BACKUP can intentionally save only headers, including files marked
NOBACKUP, as documented in the publisher's
[BACKUP manual](https://docs.vmssoftware.com/vsi-openvms-system-management-utilities-reference-manual-volume-i-a-l/).
Both observed B savesets omit contents for INDEXF.SYS, BITMAP.SYS, BADBLK.SYS,
PAGEFILE.SYS and SWAPFILE.SYS. This is not implemented as a filename exception.

Zero-length data records at block boundaries do not advance the VBN. The
saved page/swap-file attributes use FFBYTE512 (the end of the indicated block),
equivalent to byte0 of the next VBN. Tests cover both cases, cross-record reads,
EOF/slack bounds, missing versus empty contents, partial chains and bad metadata.

`ValidateHeaderChecksum` checks the 256-byte block header using reflected
CRC-16 (polynomial `0xa001`, initial value zero, no final XOR). Bytes36–39
(the block CRC) and254–255 (the header CRC) are treated as zero. The result
matches the little-endian word at254. An independent Starlark probe verified
this rule on all660 VMS2055.A headers, including the60 redundancy blocks.
The native tests use a constructed byte ramp and independently computed CRC,
check corruption at every byte, and confirm validation does not mutate input.
This header check does not establish payload integrity.

`ValidateBlockChecksums` additionally checks standard IEEE CRC-32 over the
entire block, again treating both checksum fields as zero. This uses the
standard initial and final XORs (`0xffffffff`); the stored value is the
little-endian longword at36. All660 blocks also match an independent bitwise
Starlark CRC-32 probe. Tests include corruption at every byte, truncated and
extended blocks, framing errors, limit checks, and a parity mismatch whose
own CRCs are valid.

Native REPL validation covers22 savesets on the VMS5.5-2 and5.5-2H4 discs:
7,963 blocks,682 verified XOR redundancy payloads and25,934 records. The
1,303 native VMS2055.A record offsets, sizes, kinds, flags and addresses exactly
match the independent Starlark framing probe. Payloads remain borrowed source
views; no extracted intermediate files or host decoder are involved.

Independent Starlark probes of VMS2055.A walk660 blocks, distinguish60 XOR
redundancy blocks, and recover70 file metadata/data chains. All chains have
consecutive virtual block positions and enough stored bytes for logical EOF.
The64 sequential variable-record files parse to exact RMS EOF. Four files
are fixed-record executables; two are indexed RMS files, which need their
own record/index decoder. Native file reconstruction across all22 savesets now
matches the independent Starlark assembly for every name, logical/stored size,
missing-content marker and available payload SHA256. This comparison validates
file assembly independently; both paths use the native block reader, whose
separate framing comparison is described above.

BACKUP redundancy groups are documented in the publisher's
[GROUP_SIZE contract](https://docs.vmssoftware.com/vsi-openvms-system-management-utilities-reference-manual-volume-i-a-l/).
The observed record grammar and independent file hashes remain local reports;
committed tests contain constructed blocks and metadata, not media payloads.
