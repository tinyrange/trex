package repo

// editExtents shares the unchanged prefix and suffix across arbitrary insertion
// boundaries. Multi-region matching is deliberately left to future compaction.
func editExtents(old, next []byte) []Extent {
	prefix := 0
	for prefix < len(old) && prefix < len(next) && old[prefix] == next[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(old)-prefix && suffix < len(next)-prefix && old[len(old)-1-suffix] == next[len(next)-1-suffix] {
		suffix++
	}
	var out []Extent
	if prefix > 0 {
		out = append(out, Extent{Length: uint64(prefix)})
	}
	if n := len(next) - prefix - suffix; n > 0 {
		out = append(out, Extent{Length: uint64(n), Data: next[prefix : prefix+n]})
	}
	if suffix > 0 {
		out = append(out, Extent{Offset: uint64(len(old) - suffix), Length: uint64(suffix)})
	}
	return out
}
