package uup

import "testing"

func TestCBSParentDisplaySetUsesOrdinaryParentState(t *testing.T) {
	for _, state := range []uint32{CBSStateAbsent, CBSStateStaged, CBSStateSuperseded, CBSStateInstalled} {
		parent := cbsIntentManifest(t, "SNMP", "neutral", `<update name="SNMP"/>`)
		child := cbsIntentManifest(t, "Provider", "neutral", `<update name="Provider"><applicable disposition="detect"><detectUpdate><parent name="SNMP" set="display"/></detectUpdate></applicable></update>`)
		index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: parent, IntendedState: state}, {Manifest: child, IntendedState: CBSStateInstalled, Parents: []AssemblyIdentity{parent.Identity}}})
		if err != nil {
			t.Fatal(err)
		}
		value, err := index.ApplicableUpdateState(child.Identity, "Provider")
		if err != nil || value.RawState != state || value.IntendedState != state {
			t.Fatalf("parent %x: %+v %v", state, value, err)
		}
	}
	for _, reference := range []string{`<parent name="SNMP" set="display"/>`, `<parent name="SNMP" set="unknown"/>`, `<update name="Provider" set="display"/>`} {
		child := cbsIntentManifest(t, "Provider", "neutral", `<update name="Provider"><applicable disposition="detect"><detectUpdate>`+reference+`</detectUpdate></applicable></update>`)
		index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: child, IntendedState: CBSStateInstalled}})
		if err != nil {
			t.Fatal(err)
		}
		value, err := index.ApplicableUpdateState(child.Identity, "Provider")
		if reference == `<parent name="SNMP" set="display"/>` {
			if err != nil || value.RawState != CBSStateAbsent {
				t.Fatalf("missing parent %+v %v", value, err)
			}
		} else if err == nil {
			t.Fatalf("accepted unsupported reference %s", reference)
		}
	}
}
