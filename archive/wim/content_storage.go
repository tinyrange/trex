package wim

import "strings"

// An apply traversal groups its persistent readers separately from transient
// directory/tree bookkeeping. Each reader owns only its slab and path block,
// not an allocator or the other traversals. Slots are never reused.
type contentFileStore struct {
	archive *Archive
	files   []contentFile
	next    int
	paths   strings.Builder
}

func (s *contentFileStore) newFile(e entry) *contentFile {
	if s.next == len(s.files) {
		s.files = make([]contentFile, 128)
		s.next = 0
	}
	f := &s.files[s.next]
	s.next++
	if s.paths.Cap()-s.paths.Len() < len(e.path) {
		s.paths = strings.Builder{}
		s.paths.Grow(max(64<<10, len(e.path)))
	}
	start := s.paths.Len()
	s.paths.WriteString(e.path)
	e.path = s.paths.String()[start:]
	s.archive.initContentFile(f, e)
	return f
}

// Backings are built before archive publication. Reference imports retain
// their original stable addresses; sync.Once state must never be relocated.
func (w *Archive) newResourceBacking(location wimResourceLocation) *wimResourceBacking {
	if w.backingNext == len(w.backingSlab) {
		w.backingSlab = make([]wimResourceBacking, 128)
		w.backingNext = 0
	}
	backing := &w.backingSlab[w.backingNext]
	w.backingNext++
	backing.archive = location.archive
	backing.external = location.external
	backing.resource = location.resource
	return backing
}
