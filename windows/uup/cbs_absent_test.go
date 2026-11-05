package uup

import "testing"

func TestCBSAbsentFeatureDependencyAndSelectedPayload(t *testing.T) {
	// NetFx3's absent default gates other installed wrappers' package references.
	m := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="NetFx3"><selectable disposition="absent"><detectNone default="false"/></selectable></update><update name="Content"><applicable disposition="detect"><detectUpdate><update name="NetFx3"/></detectUpdate></applicable>`+ownerChild+`</update>`)
	input := CBSPackageIntent{Manifest: m, IntendedState: CBSStateInstalled}
	got, err := planTestOwners([]CBSPackageIntent{input})
	if err == nil || got != nil {
		t.Fatal("absent detector state must require removal policy", got, err)
	}
	input.SelectableChoices = map[string]bool{"NetFx3": true}
	got, err = planTestOwners([]CBSPackageIntent{input})
	if err != nil || len(got) != 1 || got[0].Value() != 0x30070 {
		t.Fatal(got, err)
	}
	// Defender definitions' absent disposition does not remove selected content.
	input.Manifest = cbsIntentManifest(t, "Wrapper", "neutral", `<update name="Definitions"><selectable disposition="absent"><detectNone default="true"/></selectable>`+ownerChild+`</update>`)
	input.SelectableChoices = nil
	got, err = planTestOwners([]CBSPackageIntent{input})
	if err != nil || len(got) != 1 || got[0].Value() != 0x30070 {
		t.Fatal(got, err)
	}
	input.SelectableChoices = map[string]bool{"Definitions": false}
	if got, err := planTestOwners([]CBSPackageIntent{input}); err == nil || got != nil {
		t.Fatal("unimplemented owner removal accepted", got, err)
	}
}
