package uup

// Lookup maps borrow the immutable graph records instead of duplicating each
// large record in a separately allocated map value. Return value copies to
// callers so reconstruction cannot mutate the admitted graph through a lookup.
func (s *CumulativeStage) expressTarget(key string) (DeltaPayload, bool) {
	p, ok := s.expressByTarget[key]
	if !ok {
		return DeltaPayload{}, false
	}
	return *p, true
}
func (s *CumulativeStage) canonicalTarget(key string) (DeltaPayload, bool) {
	p, ok := s.canonicalByTarget[key]
	if !ok {
		return DeltaPayload{}, false
	}
	return *p, true
}

func (s *CumulativeStage) candidateName(candidate int) string {
	if candidate > 0 {
		return s.Graph.Payloads[candidate-1].Target.Name
	}
	return s.Graph.Carries[-candidate-1].Target.Name
}
