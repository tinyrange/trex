# Windows 95 RTM CREG record placement

The RTM RGDB allocator shares the later Windows 9x allocation-extent rule:
a block begins with a 4 KiB extent and grows in 8 KiB extents. Small key records
must not begin in one extent and finish in the next. When necessary, the writer
extends the preceding record's allocation with zero padding, leaving its used
length unchanged. Block free-space accounting includes the padding. Records
larger than 4 KiB retain their separate large-record handling.

The VB4 installation exposed this constraint during Windows registry startup.
The native reader could parse and roundtrip every key and value while Windows
reported a Registry Problem. A matched base image booted normally. A controlled
rewrite retained the full installed files, registry values and block/slot
identities and padded small records at the allocation boundaries; the resulting
image booted and the IDE reached its compiler dialog normally. Fresh images
using the final native encoder subsequently passed the VB4 compile/independent-run
proof and Office95 Word/Excel save/edit/reopen proofs. Merely aligning
records to DWORDs did not resolve the failure and is not part of the fix.

The regression test spans multiple blocks, verifies every value after parsing,
checks that records do not straddle extent boundaries, and validates padding
and complete free-space accounting. Navigation records retain RTM's dense
layout; they are not converted to the later paged navigation format.
