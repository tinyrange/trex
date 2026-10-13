# Read-only XFS views

`filesystem.xfs(file, maximum_entries=1000000, realtime_file=None)` reads
version-4 and checksum-protected version-5 filesystem trees without mounting or
replaying the log. Files, symlinks and directories remain portable file views;
symlinks are never followed.

Data forks can be local, inode-resident extent lists or multi-level bmap btrees.
Tree levels, capacity-based pointer positions, separator ranges, siblings,
cycles/aliases and exact extent counts are checked. Sparse/unwritten ranges
read as zeros; physical and logical ranges are validated before publishing a
view. A separate realtime device must be passed explicitly; realtime extents
address that device linearly, not through allocation-group encoded addresses.

Version-5 superblocks, v3 inodes, BMA3 trees and directory metadata are checked
with CRC32C. Metadata UUID, inode owner and physical basic-block addresses are
also checked. META_UUID volumes use their metadata UUID. Directory formats 1,
2 and 3 and file-type extensions are supported. Version-1 directory btrees and
bmap data-fork trees are distinct structures.

This is not filesystem repair, a builder or journal recovery. Unsupported
incompatible feature bits (including bigtime and large-extent-count inode
layouts) fail explicitly. External log contents and attribute-fork payloads
are not interpreted. Passing a realtime file is not automatic device discovery.

Layouts follow the XFS project's
[on-disk format documentation](https://www.kernel.org/pub/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf)
and metadata structure declarations. No filesystem driver implementation is
copied. Multi-level btrees, realtime sparse/unwritten reads, v5 CRCs and identity
checks have generated corruption tests; original IRIX v4 miniroots are also
read and validated. Modern v5/realtime coverage is synthetic, not a claim that
IRIX distributions contain those generations.
