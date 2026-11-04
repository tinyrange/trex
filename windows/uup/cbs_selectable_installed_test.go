package uup

import "testing"

func TestCBSSelectableInstalledStillHonorsApplicabilityAndPackageCap(t *testing.T) {
	// cbscore 26100.9441 maps "installed" to 0x70 in the enum table at
	// 0x366a30. GetApplicableSelectableState loads the disabled disposition
	// at 0x53aae and takes min(applicability, disposition) at 0x53ac8.
	for _, tc := range []struct {
		name                string
		app                 string
		intent, raw, capped uint32
	}{
		{"package cap", "", CBSStateStaged, CBSStateInstalled, CBSStateStaged},
		{"failed applicability", `<applicable disposition="staged"><detectNone default="false"/></applicable>`, CBSStateInstalled, CBSStateStaged, CBSStateStaged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := cbsIntentManifest(t, "WinPE", "neutral", `<update name="cmdlets">`+tc.app+`<selectable disposition="installed"><detectNone default="false"/></selectable></update>`)
			index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: tc.intent}})
			if err != nil {
				t.Fatal(err)
			}
			state, err := index.UpdateState(m.Identity, "cmdlets")
			if err != nil || state.RawState != tc.raw || state.IntendedState != tc.capped {
				t.Fatalf("got %+v %v, want raw=%#x capped=%#x", state, err, tc.raw, tc.capped)
			}
		})
	}
}
