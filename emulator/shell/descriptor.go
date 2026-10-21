package shell

import (
	"io"
	"sync"
	"sync/atomic"
)

// The final descriptor reference owns the virtual open description. Dup and
// subshells share offsets; restoring a temporary redirect releases its handle.
type fileOwner struct {
	closer     io.Closer
	references atomic.Int64
}

func (d descriptor) retain() {
	if d.owner != nil {
		d.owner.references.Add(1)
	}
}
func (d descriptor) release() {
	if d.owner != nil && d.owner.references.Add(-1) == 0 {
		d.owner.closer.Close()
	}
}
func cloneDescriptors(source map[int]descriptor) map[int]descriptor {
	result := make(map[int]descriptor, len(source))
	for n, d := range source {
		d.retain()
		result[n] = d
	}
	return result
}
func closeDescriptors(table map[int]descriptor) {
	for _, d := range table {
		d.release()
	}
}
func (s *shell) setDescriptor(n int, d descriptor) {
	d.retain()
	if old, ok := s.fds[n]; ok {
		old.release()
	}
	s.fds[n] = d
}
func (s *shell) closeDescriptor(n int) {
	if d, ok := s.fds[n]; ok {
		d.release()
		delete(s.fds, n)
	}
}

// Duplicates share a read offset even when the caller supplies an ordinary
// strings.Reader. This lock is per open description, not a global I/O lock.
type lockedReader struct {
	mu *sync.Mutex
	r  io.Reader
}

func (r lockedReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.r.Read(p)
}

// Descriptor closure, not shell-list completion, determines EOF: background
// descendants may still hold a duplicate of a pipeline or substitution output.
type captureEnd struct{ done chan struct{} }

func (c captureEnd) Close() error { close(c.done); return nil }

// A zero-length Unix pipe write transmits no record. io.Pipe otherwise makes
// a reader observe (0,nil), which can falsely exhaust bufio's progress guard.
type pipeOutput struct{ io.Writer }

func (p pipeOutput) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return p.Writer.Write(data)
}
