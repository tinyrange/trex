# Observed IBM i COPYDIR profile

`OpenCopyDirectory(source, maximumSegments, maximumLIDs, maximumBytes)` indexes
borrowed saved-segment payloads and the active LIDDIR table. A zero byte limit
permits unbounded borrowed source length; metadata counts and header reads remain
bounded. Positive limits constrain copied payload length. No restored memory
image, omitted-page zeros or executable load map is fabricated.

The qualified profile has a 16KiB header beginning with invariant EBCDIC
`COPYDIR `. The +24 word contains 0x40000000 and a 24-bit record count; +28 gives
copied body length. Records are 64 bytes at +192: saved base +16, span +24,
opaque flags +28, body-relative offset +40 and copied length +48. Each nonempty
record omits the segment's first 4096-byte page; copied length is span minus
4096. Body extents must be contiguous and exhaust the declared source length;
saved spans must not overlap or overflow. Unmapped records may contain opaque
control fields (the real medium includes an f0 control marker); their address,
span, payload offset and payload length must remain zero. Raw header is preserved.

`SavedAt(address,size)` borrows only a completely present saved range. It fails
for omitted pages, unrepresented addresses, overflowing or cross-segment ranges.
Saved-storage addresses are explicitly distinct from linked/physical execution
addresses. Disk-sector fields in the LID table are never used as file offsets.

Automatic `ibmi_copydir` browsing exposes header.bin, directory.bin, metadata.json,
segments/<16-hex-saved-base>.bin and components/<8-hex-LID>.bin when the entire
component is present. Metadata retains all LIDs, with an explicit unavailable
reason when a declared component contains an omitted/unmapped range. Partially
available components are not silently padded or presented as complete files.

On the RS750-J input this indexes 119 copied segments and 1008 LIDs; 32 LIDs
cannot be exposed as complete files. Three whole-content hash anchors reproduce
the independent IMD copies. Synthetic tests cover holes, collisions, bounds,
budgets and opaque reserved fields. A bounded fuzz target exercises metadata
parsing without needing proprietary payloads.
