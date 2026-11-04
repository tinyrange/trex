package uup

import (
	"strings"
	"testing"
)

func TestCBSOwnerIntentCapabilityDependency(t *testing.T) {
	// A capability-backed selector is queried by a package wrapper. Its default
	// intent is distinct from capability execution's absence/removal permission.
	for _, flag := range []string{"true", "false"} {
		for _, selected := range []string{"true", "false"} {
			root := cbsIntentManifest(t, "Capability-Parent", "neutral", `<update name="Feature"><selectable disposition="staged" absentIfCapabilityAbsent="`+flag+`"><detectNone default="`+selected+`"/></selectable><capability><capabilityIdentity name="Test.Feature" version="0.0.1.0"/></capability></update>`)
			child := cbsIntentManifest(t, "Capability-Wrapper", "neutral", `<update name="Content"><applicable disposition="detect"><detectUpdate><parent name="Feature"/></detectUpdate></applicable>`+ownerChild+`</update>`)
			inputs := []CBSPackageIntent{{Manifest: root, IntendedState: CBSStateInstalled}, {Manifest: child, IntendedState: CBSStateInstalled, Parents: []AssemblyIdentity{root.Identity}}}
			owners, err := planTestOwners(inputs)
			want := uint32(0x30040)
			if selected == "true" {
				want = 0x30070
			}
			if err != nil || len(owners) != 1 || owners[0].Value() != want {
				t.Fatalf("flag=%s selected=%s: %+v %v", flag, selected, owners, err)
			}
		}
	}
	for _, flag := range []string{"", "TRUE", "1", "absent"} {
		m := cbsIntentManifest(t, "Invalid", "neutral", `<update name="Content"><selectable disposition="staged" absentIfCapabilityAbsent="`+flag+`"><detectNone default="true"/></selectable>`+ownerChild+`</update>`)
		if got, err := planTestOwners([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateInstalled}}); err == nil || got != nil || !strings.Contains(err.Error(), "absentIfCapabilityAbsent") {
			t.Fatal(got, err)
		}
	}
}
