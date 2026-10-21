package shell

import (
	"fmt"
	"io/fs"
	"time"
)

// SetModTime imports an explicit source timestamp without reading a host clock.
// Future mutations remain strictly newer than every imported timestamp.
func (m *MemoryFS) SetModTime(name string, modified time.Time) error {
	if err := validPath(name); err != nil {
		return err
	}
	stamp := modified.UnixNano()
	if !time.Unix(0, stamp).Equal(modified) || stamp > 1<<63-1-1<<32 {
		return fmt.Errorf("shell: modification time outside logical clock range")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[name]
	if !ok {
		return pathError("setmodtime", name, fs.ErrNotExist)
	}
	n.modified = modified
	if stamp > m.clock {
		m.clock = stamp
	}
	return nil
}
