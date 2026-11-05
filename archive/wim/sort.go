package wim

type foldedEntrySorter struct {
	entries []entry
	keys    []string
}

func (s foldedEntrySorter) Len() int { return len(s.entries) }
func (s foldedEntrySorter) Less(i, j int) bool {
	if s.entries[i].isDir != s.entries[j].isDir {
		return s.entries[i].isDir
	}
	return s.keys[i] < s.keys[j]
}
func (s foldedEntrySorter) Swap(i, j int) {
	s.entries[i], s.entries[j] = s.entries[j], s.entries[i]
	s.keys[i], s.keys[j] = s.keys[j], s.keys[i]
}
