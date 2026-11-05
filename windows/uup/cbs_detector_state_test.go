package uup

import (
	"fmt"
	"strings"
	"testing"
)

func TestCBSDetectorFailureStates(t *testing.T) {
	for _, disposition := range []string{"detect", "staged"} {
		for _, parentState := range []uint32{CBSStateStaged, CBSStateSuperseded, CBSStateInstalled} {
			t.Run(fmt.Sprintf("%s/%x", disposition, parentState), func(t *testing.T) {
				parent := cbsIntentManifest(t, "Parent", "neutral", `<update name="feature"/>`)
				wrapper := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="content"><applicable disposition="`+disposition+`"><detectUpdate><parent name="feature"/></detectUpdate></applicable>`+ownerChild+`</update>`)
				inputs := []CBSPackageIntent{{Manifest: parent, IntendedState: parentState}, {Manifest: wrapper, IntendedState: CBSStateInstalled, Parents: []AssemblyIdentity{parent.Identity}}}
				owners, err := planTestOwners(inputs)
				want := parentState
				if disposition == "staged" && parentState < CBSStateInstalled {
					want = CBSStateStaged
				}
				if err != nil || len(owners) != 1 || owners[0].State != want {
					t.Fatalf("%+v %v want %x", owners, err, want)
				}
			})
		}
	}
}

func TestCBSLocalDetectorDoesNotInheritContainingCap(t *testing.T) {
	// The local installed feature must satisfy the staged-disposition predicate
	// before the superseded containing package caps the emitted owner to 0x50.
	m := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="feature"/><update name="content"><applicable disposition="staged"><detectUpdate><update name="feature"/></detectUpdate></applicable>`+ownerChild+`</update>`)
	owners, err := planTestOwners([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateSuperseded}})
	if err != nil || len(owners) != 1 || owners[0].State != CBSStateSuperseded {
		t.Fatal(owners, err)
	}
}

func TestCBSDetectorParentMaxAndConjunctionMin(t *testing.T) {
	low := cbsIntentManifest(t, "Low", "neutral", `<update name="feature"/><update name="other"><selectable disposition="staged"><detectNone default="false"/></selectable></update>`)
	high := cbsIntentManifest(t, "High", "neutral", `<update name="feature"/>`)
	body := `<update name="content"><applicable disposition="detect"><detectUpdate><parent name="feature"/></detectUpdate>%s</applicable>` + ownerChild + `</update>`
	for _, extra := range []bool{false, true} {
		predicate := ""
		want := CBSStateSuperseded
		if extra {
			predicate = `<detectUpdate><parent name="other"/></detectUpdate>`
			want = CBSStateStaged
		}
		wrapper := cbsIntentManifest(t, "Wrapper", "neutral", fmt.Sprintf(body, predicate))
		owners, err := planTestOwners([]CBSPackageIntent{{Manifest: low, IntendedState: CBSStateStaged}, {Manifest: high, IntendedState: CBSStateSuperseded}, {Manifest: wrapper, IntendedState: CBSStateInstalled, Parents: []AssemblyIdentity{low.Identity, high.Identity}}})
		if err != nil || len(owners) != 1 || owners[0].State != want {
			t.Fatalf("extra=%v: %+v %v want %x", extra, owners, err, want)
		}
	}
}

func TestCBSApplicabilityAlternativesDoNotMaskSelection(t *testing.T) {
	for _, selected := range []bool{false, true} {
		m := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="disabled"><selectable disposition="absent"><detectNone default="false"/></selectable></update><update name="enabled"/><update name="content"><applicable disposition="detect"><detectUpdate><update name="disabled"/></detectUpdate></applicable><applicable disposition="detect"><detectUpdate><update name="enabled"/></detectUpdate></applicable><selectable disposition="staged"><detectNone default="false"/></selectable>`+ownerChild+`</update>`)
		owners, err := planTestOwners([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateInstalled, SelectableChoices: map[string]bool{"content": selected}}})
		want := CBSStateStaged
		if selected {
			want = CBSStateInstalled
		}
		if err != nil || len(owners) != 1 || owners[0].State != want {
			t.Fatal(owners, err)
		}
	}
}

func TestCBSMissingParentDispositionIsNotImplicitStaging(t *testing.T) {
	for _, disposition := range []string{"detect", "staged"} {
		m := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="content"><applicable disposition="`+disposition+`"><detectUpdate><parent name="missing"/></detectUpdate></applicable>`+ownerChild+`</update>`)
		owners, err := planTestOwners([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateInstalled}})
		if disposition == "detect" {
			if err == nil || !strings.Contains(err.Error(), "requires removal policy") || owners != nil {
				t.Fatal(owners, err)
			}
		} else if err != nil || len(owners) != 1 || owners[0].State != CBSStateStaged {
			t.Fatal(owners, err)
		}
	}
}
