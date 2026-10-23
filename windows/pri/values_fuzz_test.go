package pri

import "testing"

func FuzzResourceValues(f *testing.F) {
	s, sections := stringFixture(4, []byte("value\x00"), false, false)
	a, _ := s.Payload()
	b, _ := decisionsFixture().Payload()
	c, _ := sections[0].Payload()
	f.Add(a, b, c, uint32(5))
	f.Fuzz(func(t *testing.T, a, b, c []byte, index uint32) {
		if len(a)+len(b)+len(c) > 1<<20 {
			t.Skip()
		}
		m, err := ParseResourceMap(resourceSection(ResourceMap2Type, a))
		if err != nil {
			return
		}
		d, err := ParseDecisions(resourceSection(DecisionsType, b))
		if err != nil {
			return
		}
		_, _ = m.SingleString(index, d, []Section{resourceSection("[mrm_dataitem] \x00", c)})
	})
}
