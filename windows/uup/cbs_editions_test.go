package uup

import (
	"strings"
	"testing"
)

const editionGate = `<customInformation xmlns="urn:schemas-microsoft-com:asm.v3"><e:EnableSelectabilityForEditions xmlns:e="urn:schemas-microsoft-com:asm.v3"><e:EnableSelectabilityForEdition name="Microsoft-Windows-IoTEnterpriseSEdition"/><e:EnableSelectabilityForEdition name="Microsoft-Windows-IoTEnterpriseSKEdition"/></e:EnableSelectabilityForEditions></customInformation>`

func TestCBSOwnerEditionGate(t *testing.T) {
	body := `<update name="Feature"><selectable disposition="staged"><detectNone default="false"/>` + editionGate + `</selectable>` + ownerChild + `</update>`
	m := cbsIntentManifest(t, "Wrapper", "neutral", body)
	input := CBSPackageIntent{Manifest: m, IntendedState: CBSStateInstalled, EditionNames: []string{"Microsoft-Windows-ProfessionalEdition"}}
	check := func(want uint32) {
		t.Helper()
		got, err := planTestOwners([]CBSPackageIntent{input})
		if err != nil || len(got) != 1 || got[0].Value() != want {
			t.Fatalf("%+v %v want=%x", got, err, want)
		}
	}
	// A disabled selector does not disable the child: CBS ignores its default.
	check(0x30070)
	input.EditionNames = append(input.EditionNames, "microsoft-windows-iotenterprisesedition")
	check(0x30040)
	input.SelectableChoices = map[string]bool{"Feature": true}
	check(0x30070)
	input.IntendedState = CBSStateStaged
	check(0x30040)
	input.EditionNames = input.EditionNames[:1]
	if got, err := planTestOwners([]CBSPackageIntent{input}); err == nil || got != nil {
		t.Fatal("edition-disabled choice accepted", got, err)
	}
	input.SelectableChoices = nil
	input.IntendedState = CBSStateInstalled
	// Native removable wrappers use absent, but on Professional the entire
	// selector is disabled. This is not support for removing selected packages.
	input.Manifest = cbsIntentManifest(t, "Wrapper", "neutral", strings.Replace(body, `disposition="staged"`, `disposition="absent"`, 1))
	check(0x30070)
	input.EditionNames = []string{"Microsoft-Windows-IoTEnterpriseSEdition"}
	if got, err := planTestOwners([]CBSPackageIntent{input}); err == nil || got != nil {
		t.Fatal("unimplemented removal accepted", got, err)
	}
}

func TestCBSOwnerEditionGateRejectsUnknownPolicy(t *testing.T) {
	for _, gate := range []string{
		strings.Replace(editionGate, `xmlns="urn:schemas-microsoft-com:asm.v3"`, `xmlns="urn:foreign"`, 1),
		strings.Replace(editionGate, "EnableSelectabilityForEdition name", "Unknown name", 1),
		strings.Replace(editionGate, `name="Microsoft-Windows-IoTEnterpriseSEdition"`, `unexpected="x" name="Microsoft-Windows-IoTEnterpriseSEdition"`, 1),
		editionGate + editionGate,
		`<customInformation/>`,
	} {
		m := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="Feature"><selectable disposition="staged"><detectNone default="false"/>`+gate+`</selectable>`+ownerChild+`</update>`)
		got, err := planTestOwners([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateInstalled, EditionNames: []string{"Microsoft-Windows-ProfessionalEdition"}}})
		if err == nil || got != nil {
			t.Fatal("unknown policy accepted", gate, got, err)
		}
	}
	m := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="Feature"><selectable disposition="staged"><detectNone default="true"/>`+editionGate+`</selectable>`+ownerChild+`</update>`)
	if got, err := planTestOwners([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateInstalled}}); err == nil || got != nil {
		t.Fatal("missing session edition accepted", got, err)
	}
}
