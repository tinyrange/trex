# FAT12 root-directory capacity

`filesystem.fat12(..., root_entries=512)` accepts an explicit root capacity.
It must be a positive multiple of 16, at most 65520. The builder consistently
uses the value in the BPB, fixed-root extent, data-cluster origin and capacity
checks; overflowing root contents are rejected. Existing defaults and FAT16
construction are unchanged. Use `chs=(80,2,18), root_entries=224` for the Gate2
1.44-MiB DOS6.22 behavioral-workload floppy.

This policy follows a bounded live discriminator, not a speculative global
format change. With a 512-entry root, original DOS6.22's floppy drive parameters
reported first-data sector 19 while the native image's data started at 51.
An absolute read of sector52 returned the exact intended registration text;
a DOS file read/copy returned an equal-sized zero buffer. The independent
original Setup base reproduced the same symptom. Changing only root capacity
to224 made file reads/copies exact; the media descriptor remained F8. The exact
original driver's arithmetic is not claimed established. Other FAT12 consumers
are not silently changed to this policy.

Prior controls rejected Regedit's silent switch, media descriptor F0 alone,
and generated-versus-byte-identical-in-memory backing as the primary cause.
The rejected media-descriptor API candidate was removed. No host extraction,
formatting or intermediate media file is used. Source and evidence remain
separate from the copyrighted original DOS media.

Native tests check capacities128/224/512 against BPB fields, root/data offsets,
cluster-chain contents, invalid capacities and root overflow. Live read and
absolute-sector/DPB observations are retained in Gate2 pilots p33–p43.
