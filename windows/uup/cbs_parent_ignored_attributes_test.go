package uup

import "testing"

// Native ProcessVersionCompareAttribute dispatches service/distribution to
// its next-attribute branch, not the comparison enum parser. In particular,
// GE on LIP parents must not cause an error or make an absent parent match.
func TestCBSParentIgnoredVersionAttributes(t *testing.T) {
	for _, value := range []string{"EQ", "GE", "", "not-an-operator"} {
		m := parentStateManifest(t, `<parent serviceCompare="`+value+`" distributionCompare="`+value+`"><assemblyIdentity name="feature"/></parent>`)
		for _, state := range []uint32{0, 0x40, 0x50, 0x70} {
			calls := 0
			got, err := EvaluateCBSPackageParents(m, CBSParentEvaluation{Resolve: func(ref AssemblyReference) (uint32, error) {
				calls++
				if ref.Identity.Name != "feature" {
					t.Fatalf("changed reference: %+v", ref)
				}
				return state, nil
			}})
			if err != nil || got != state || calls != 1 {
				t.Fatalf("value %q state %#x: got %#x calls %d error %v", value, state, got, calls, err)
			}
		}
	}
}
