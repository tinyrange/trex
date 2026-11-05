package uup

import "testing"

func TestCBSSelectableOmittedDispositionUsesNativeStagedDefault(t *testing.T) {
	// ProcessUpdateGroupType in cbscore 26100.9441 initializes SELECTABLE_TYPE
	// at 0x1e20c to 0x40. ProcessSelectableType changes it only for an explicit
	// disposition. This shape occurs in NanoServer IIS metadata in the LCU.
	for _, tc := range []struct {
		name, xml string
		want      uint32
		bad       bool
	}{
		{"disabled omitted", `<selectable><detectNone default="false"/></selectable>`, CBSStateStaged, false},
		{"enabled omitted", `<selectable><detectNone default="true"/></selectable>`, CBSStateInstalled, false},
		{"explicit absent", `<selectable disposition="absent"><detectNone default="false"/></selectable>`, CBSStateAbsent, false},
		{"explicit staged", `<selectable disposition="staged"><detectNone default="false"/></selectable>`, CBSStateStaged, false},
		{"disabled installed", `<selectable disposition="installed"><detectNone default="false"/></selectable>`, CBSStateInstalled, false},
		{"enabled installed", `<selectable disposition="installed"><detectNone default="true"/></selectable>`, CBSStateInstalled, false},
		{"explicit empty", `<selectable disposition=""><detectNone default="true"/></selectable>`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := cbsIntentManifest(t, "IIS", "neutral", `<update name="IIS-WebServer">`+tc.xml+`</update>`)
			index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateInstalled}})
			if err != nil {
				t.Fatal(err)
			}
			state, err := index.ApplicableUpdateState(m.Identity, "IIS-WebServer")
			if tc.bad {
				if err == nil {
					t.Fatal("accepted empty disposition")
				}
				return
			}
			if err != nil || state.RawState != tc.want {
				t.Fatalf("got %+v %v, want %#x", state, err, tc.want)
			}
		})
	}
}
