package native

import (
	"io/fs"
	"syscall"
)

// Space follows cc's host filesystem accounting, using a rooted descriptor
// rather than re-resolving the original host path after a directory rename.
func (r *Root) Space() (uint64, uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, 0, fs.ErrClosed
	}
	f, e := r.root.Open(".")
	if e != nil {
		return 0, 0, e
	}
	defer f.Close()
	var st syscall.Statfs_t
	if e := syscall.Fstatfs(int(f.Fd()), &st); e != nil {
		return 0, 0, e
	}
	return st.Blocks * uint64(st.Bsize), st.Bavail * uint64(st.Bsize), nil
}
