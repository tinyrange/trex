package uup

// ReleaseReadCaches releases reconstructible construction working sets.
// It preserves graph identities, source/predecessor bindings and all validation.
func (s *CumulativeStage) ReleaseReadCaches() {
	if s == nil {
		return
	}
	s.canonicalMu.Lock()
	s.canonicalCache = make(map[string][]byte)
	s.canonicalRetained = 0
	s.compactTargets = true
	s.packedTargets = nil
	s.canonicalMu.Unlock()
	s.Metadata.ReleaseReadCaches()
	s.metadataCAB.ReleaseReadCaches()
	for _, a := range s.metadataArchives {
		a.wim.ReleaseReadCaches()
		a.cab.ReleaseReadCaches()
	}
}
