package shell

import "io/fs"

// SetAppend updates this open-file description without changing its offset.
func (f *memoryFile) SetAppend(enabled bool) error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if f.closed {
		return fs.ErrClosed
	}
	if enabled {
		f.flags |= Append
	} else {
		f.flags &^= Append
	}
	return nil
}
func (f *nullFile) SetAppend(bool) error { return nil }
