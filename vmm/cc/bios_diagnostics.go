package cc

// Keep bounded unsupported firmware call counters, not an unbounded boot log.
func (p *pc) observeUnsupportedBIOS(name string) {
	if p.unsupportedBIOS == nil {
		p.unsupportedBIOS = make(map[string]uint64)
	}
	if len(p.unsupportedBIOS) < 64 || p.unsupportedBIOS[name] != 0 {
		p.unsupportedBIOS[name]++
	}
}
