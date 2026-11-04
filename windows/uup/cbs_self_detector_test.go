package uup

import "testing"

func TestCBSExactLocalSelfDetectorIsRemovedDuringInitialization(t *testing.T) {
	for _, reference := range []string{"IIS-Security", "iis-security"} {
		m := cbsIntentManifest(t, "NanoServer-IIS", "neutral", `<update name="IIS-Security"><applicable disposition="detect"><detectUpdate><update name="`+reference+`"/></detectUpdate></applicable></update>`)
		index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateStaged}})
		if err != nil {
			t.Fatal(err)
		}
		value, err := index.ApplicableUpdateState(m.Identity, "iis-security")
		if reference != "IIS-Security" {
			if err == nil {
				t.Fatal("case-mismatched self reference silently removed")
			}
		} else if err != nil || value.RawState != CBSStateInstalled || value.IntendedState != CBSStateStaged {
			t.Fatalf("exact self: %+v %v", value, err)
		}
	}
	// A parent's equally named update is not a local self reference.
	m := cbsIntentManifest(t, "Localized-IIS", "neutral", `<update name="IIS-Security"><applicable disposition="detect"><detectUpdate><parent name="IIS-Security"/></detectUpdate></applicable></update>`)
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateInstalled}})
	if err != nil {
		t.Fatal(err)
	}
	value, err := index.ApplicableUpdateState(m.Identity, "IIS-Security")
	if err != nil || value.RawState != CBSStateAbsent {
		t.Fatalf("parent was treated as local self: %+v %v", value, err)
	}
}
