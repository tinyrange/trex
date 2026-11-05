package wim

// Keep only a bounded diagnostic window, not a path/history-sized cache. The
// names are archive-internal paths and contain no host filesystem information.
func (w *Archive) noteBlobMiss(name string) {
	w.missMu.Lock()
	w.recentMisses[w.missCount%64] = name
	w.missCount++
	w.missMu.Unlock()
}
