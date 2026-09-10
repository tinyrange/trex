package pri

import "fmt"

const DecisionsType = "[mrm_decn_info]\x00"

// Decisions preserves decision cardinalities after checking the decision and
// qualifier reference tables. It does not evaluate qualifiers or pick a value.
type Decisions struct{ counts []uint16 }

func ParseDecisions(section Section) (*Decisions, error) {
	if string(section.Type[:]) != DecisionsType {
		return nil, fmt.Errorf("pri: expected decision info")
	}
	b, err := section.Payload()
	if err != nil {
		return nil, err
	}
	if len(b) < 12 {
		return nil, fmt.Errorf("pri: short decision info")
	}
	nb, nq, ns, nd, nr, nc := int(le.Uint16(b)), int(le.Uint16(b[2:])), int(le.Uint16(b[4:])), int(le.Uint16(b[6:])), int(le.Uint16(b[8:])), int(le.Uint16(b[10:]))
	sets := 12 + 4*nd
	quals := sets + 4*ns
	bases := quals + 8*nq
	refs := bases + 12*nb
	literals := refs + 2*nr
	end := literals + 2*nc
	if end > len(b) || len(b)-end > 7 {
		return nil, fmt.Errorf("pri: invalid decision info extent")
	}
	for _, v := range b[end:] {
		if v != 0 {
			return nil, fmt.Errorf("pri: nonzero decision padding")
		}
	}
	checkRefs := func(off, count, limit int) error {
		for i := 0; i < count; i++ {
			p := b[off+4*i:]
			first, n := int(le.Uint16(p)), int(le.Uint16(p[2:]))
			if first > nr || n > nr-first {
				return fmt.Errorf("pri: decision references outside table")
			}
			for j := 0; j < n; j++ {
				if int(le.Uint16(b[refs+2*(first+j):])) >= limit {
					return fmt.Errorf("pri: invalid decision reference")
				}
			}
		}
		return nil
	}
	if err = checkRefs(12, nd, ns); err != nil {
		return nil, err
	}
	if err = checkRefs(sets, ns, nq); err != nil {
		return nil, err
	}
	for i := 0; i < nq; i++ {
		p := b[quals+8*i:]
		if int(le.Uint16(p)) >= nb || le.Uint16(p[6:]) != 0 {
			return nil, fmt.Errorf("pri: invalid qualifier record")
		}
	}
	d := &Decisions{counts: make([]uint16, nd)}
	for i := range d.counts {
		d.counts[i] = le.Uint16(b[12+4*i+2:])
	}
	return d, nil
}

func (m *ResourceMap) CandidateCount(index uint32, decisions *Decisions) (int, error) {
	it, ok := m.Resource(index)
	if !ok {
		return 0, nil
	}
	if decisions == nil || int(it.Decision) >= len(decisions.counts) {
		return 0, fmt.Errorf("pri: resource decision outside table")
	}
	n := decisions.counts[it.Decision]
	if uint64(it.FirstValue)+uint64(n) > uint64(m.ValueCount) {
		return 0, fmt.Errorf("pri: candidates outside value table")
	}
	return int(n), nil
}
