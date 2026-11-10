package uup

import "strings"

// compactStorage runs only on an unpublished completed graph, after CIX
// selection. Compacting while parsing would pin discarded CIX names through
// selected neighbours. Here every string and descriptor has runtime ownership.
func (g *CumulativeGraph) compactStorage() {
	var names graphStringStore
	names.seen = make(map[string]string)
	own := func(d *ContentDescriptor) { d.Name = names.copy(d.Name) }
	var sources []ContentDescriptor
	if g.Sources != nil {
		sources = make([]ContentDescriptor, len(g.Sources))
	}
	copy(sources, g.Sources)
	var carries []CarryPayload
	if g.Carries != nil {
		carries = make([]CarryPayload, len(g.Carries))
	}
	copy(carries, g.Carries)
	var payloads []DeltaPayload
	if g.Payloads != nil {
		payloads = make([]DeltaPayload, len(g.Payloads))
	}
	copy(payloads, g.Payloads)
	g.Sources, g.Carries, g.Payloads = sources, carries, payloads
	count := 0
	for _, p := range g.Payloads {
		for _, d := range []*ContentDescriptor{p.Basis, p.RecordBasis, p.RecordTarget} {
			if d != nil {
				count++
			}
		}
	}
	descriptors := make([]ContentDescriptor, count)
	next := 0
	for i := range g.Sources {
		own(&g.Sources[i])
	}
	for i := range g.Carries {
		own(&g.Carries[i].Target)
		own(&g.Carries[i].Source)
	}
	for i := range g.Payloads {
		p := &g.Payloads[i]
		own(&p.Target)
		own(&p.Record)
		p.RecordType = names.copy(p.RecordType)
		for _, slot := range []**ContentDescriptor{&p.Basis, &p.RecordBasis, &p.RecordTarget} {
			if *slot == nil {
				continue
			}
			descriptors[next] = **slot
			own(&descriptors[next])
			*slot = &descriptors[next]
			next++
		}
	}
}

type graphStringStore struct {
	block strings.Builder
	seen  map[string]string
}

func (s *graphStringStore) copy(value string) string {
	if value == "" {
		return ""
	}
	if result, ok := s.seen[value]; ok {
		return result
	}
	const slabBytes = 64 << 10
	if s.block.Cap()-s.block.Len() < len(value) {
		s.block = strings.Builder{}
		s.block.Grow(max(slabBytes, len(value)))
	}
	start := s.block.Len()
	s.block.WriteString(value)
	result := s.block.String()[start:]
	s.seen[value] = result
	return result
}
