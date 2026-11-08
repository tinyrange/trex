package uup

import "testing"

func TestCBSMultiReferenceDetector(t *testing.T) {
	parent := cbsIntentManifest(t, "Parent", "neutral", `<update name="staged"><selectable disposition="staged"><detectNone default="false"/></selectable></update><update name="installed"/>`)
	for _, tc := range []struct {
		name, refs string
		want       uint32
	}{
		{"first missing", `<parent name="missing"/><parent name="installed"/>`, CBSStateInstalled},
		{"second missing", `<parent name="installed"/><parent name="missing"/>`, CBSStateInstalled},
		{"maximum failure", `<parent name="staged"/><parent name="missing"/>`, CBSStateStaged},
		{"missing", `<parent name="missing"/><parent name="other"/>`, CBSStateAbsent},
		{"self removed", `<update name="content"/><parent name="staged"/>`, CBSStateStaged},
		{"empty after self removal", `<update name="content"/>`, CBSStateInstalled},
		{"empty", ``, CBSStateInstalled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := cbsIntentManifest(t, "Child", "neutral", `<update name="content"><applicable disposition="detect"><detectUpdate>`+tc.refs+`</detectUpdate></applicable></update>`)
			index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: parent, IntendedState: CBSStateInstalled}, {Manifest: child, IntendedState: CBSStateInstalled, Parents: []AssemblyIdentity{parent.Identity}}})
			if err != nil {
				t.Fatal(err)
			}
			got, err := index.ApplicableUpdateState(child.Identity, "content")
			if err != nil || got.RawState != tc.want {
				t.Fatalf("%+v %v want %x", got, err, tc.want)
			}
		})
	}
}
