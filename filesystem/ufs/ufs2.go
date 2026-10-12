package ufs

// UFS2 inode and pointer fields follow NetBSD sys/ufs/ufs/dinode.h and
// sys/ufs/ffs/fs.h; the extended-attribute variant shares this payload layout.
func (r *reader) pointer(raw []byte) uint64 {
	if r.ufs2 {
		return r.order.Uint64(raw)
	}
	return uint64(r.order.Uint32(raw))
}
