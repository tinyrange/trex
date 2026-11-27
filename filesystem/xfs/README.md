# XFS views and image construction

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

The readers leave filesystem repair and journal recovery to the OS. Unsupported
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

`filesystem.xfs_build(entries, size, uuid, label='')` generates a v4 volume
with 4 KiB filesystem blocks, 512-byte sectors, v2 directory records and
256-byte inodes. It writes the inode and free-space indexes for a single
allocation group and initializes a clean internal v1 log. The result is an
immutable sparse view of the volume. Attach it through a writable block
overlay to preserve the source while the guest makes changes.

Entry dictionaries use the shared Unix metadata fields, including modes,
UIDs, GIDs, timestamps, regular file data, symbolic links, regular-file
hard links and device identifiers. The builder takes a 16-byte volume UUID.
The caller can wrap its result in an SGI disk with `filesystem.sgi_build`.
