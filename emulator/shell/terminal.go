package shell

// Terminal is an optional stream capability. Ordinary buffers, virtual files
// and pipes are not terminals; providers may attach explicit virtual terminals.
type Terminal interface{ IsTerminal() bool }

func (r lockedReader) IsTerminal() bool { t, ok := r.r.(Terminal); return ok && t.IsTerminal() }
func (w lockedWriter) IsTerminal() bool { t, ok := w.w.(Terminal); return ok && t.IsTerminal() }
func (s *shell) terminal(fd int) bool {
	d, ok := s.fds[fd]
	if !ok {
		return false
	}
	if t, ok := d.reader.(Terminal); ok && t.IsTerminal() {
		return true
	}
	if t, ok := d.writer.(Terminal); ok && t.IsTerminal() {
		return true
	}
	return false
}
