package uup

import (
	"fmt"
	"strings"
	"testing"
)

func cbsIntentManifest(t *testing.T, name, language, contents string) *AssemblyManifest {
	t.Helper()
	m, err := ParseAssemblyManifest(strings.NewReader(fmt.Sprintf(`<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="%s" version="10.0.26100.9457" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="%s"/><package>%s</package></assembly>`, name, language, contents)))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

const ownerChild = `<package contained="false" integrate="hidden"><assemblyIdentity name="HyperV-Hypervisor-Package" version="10.0.26100.9457" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/></package>`

func TestCBSOwnerIntentLocalFeatureAndLanguageScope(t *testing.T) {
	// Native Hyper-V neutral wrapper is installed, but its child owner intent is
	// staged. The localized wrapper has the same update name with installed intent.
	neutral := cbsIntentManifest(t, "HyperV-ClientEdition-Package", "neutral", `
 <update name="HyperV-All"><selectable disposition="staged"><detectNone default="false"/></selectable></update>
 <update name="HyperV"><applicable disposition="detect"><detectUpdate><update name="HyperV-All"/></detectUpdate></applicable><selectable disposition="staged"><detectNone default="true"/></selectable></update>
 <update name="HyperV-Hypervisor"><applicable disposition="detect"><detectUpdate><update name="HyperV"/></detectUpdate></applicable><selectable disposition="staged"><detectNone default="true"/></selectable>`+ownerChild+`</update>`)
	localized := cbsIntentManifest(t, "HyperV-ClientEdition-Package", "en-US", `<update name="HyperV-Hypervisor">`+ownerChild+`</update>`)
	inputs := []CBSPackageIntent{{Manifest: neutral, IntendedState: CBSStateInstalled}, {Manifest: localized, IntendedState: CBSStateInstalled}}
	check := func(want uint32) {
		t.Helper()
		owners, err := planTestOwners(inputs)
		if err != nil {
			t.Fatal(err)
		}
		if len(owners) != 2 {
			t.Fatalf("owners=%+v", owners)
		}
		for _, o := range owners {
			expected := uint32(0x30070)
			if strings.Contains(o.Owner, "~amd64~~") {
				expected = want
			}
			if o.Value() != expected {
				t.Fatalf("owner=%+v want=%x", o, expected)
			}
		}
	}
	check(0x30040)
	inputs[0].SelectableChoices = map[string]bool{"HyperV-All": true}
	check(0x30070)
	inputs[0].SelectableChoices["HyperV-Hypervisor"] = false
	check(0x30040)
	// An explicit child selection cannot override a disabled applicability parent.
	inputs[0].SelectableChoices = map[string]bool{"HyperV-All": false, "HyperV-Hypervisor": true}
	check(0x30040)
}

func TestCBSOwnerIntentParentScopeAndPackageCap(t *testing.T) {
	p := cbsIntentManifest(t, "Feature-Parent", "neutral", `<update name="Feature"><selectable disposition="staged"><detectNone default="false"/></selectable></update>`)
	unrelated := cbsIntentManifest(t, "Unrelated", "neutral", `<update name="Feature"/>`)
	wrapper := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="Content"><applicable disposition="detect"><detectUpdate><parent name="Feature"/></detectUpdate></applicable>`+ownerChild+`</update>`)
	inputs := []CBSPackageIntent{{Manifest: p, IntendedState: CBSStateInstalled}, {Manifest: unrelated, IntendedState: CBSStateInstalled}, {Manifest: wrapper, IntendedState: CBSStateInstalled, Parents: []AssemblyIdentity{p.Identity}}}
	check := func(want uint32) {
		t.Helper()
		owners, err := planTestOwners(inputs)
		if err != nil || len(owners) != 1 || owners[0].Value() != want {
			t.Fatalf("owners=%+v err=%v want=%x", owners, err, want)
		}
	}
	check(0x30040)
	inputs[0].SelectableChoices = map[string]bool{"Feature": true}
	check(0x30070)
	inputs[2].IntendedState = CBSStateStaged
	check(0x30040)
	inputs[2].IntendedState = CBSStateInstalled
	inputs[2].Parents = nil // No defining update in a resolved parent scope.
	if got, err := planTestOwners(inputs); err == nil || got != nil {
		t.Fatal("missing parent must preserve absent detector state", got, err)
	}
}

func TestCBSOwnerIntentLiberatedOwnerAndMergedUpdates(t *testing.T) {
	child := strings.Replace(ownerChild, `integrate="hidden"`, `integrate="liberate"`, 1)
	m := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="Disabled"><selectable disposition="staged"><detectNone default="false"/></selectable>`+child+`</update><update name="Enabled">`+child+`</update>`)
	got, err := planTestOwners([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateInstalled}})
	if err != nil || len(got) != 1 || got[0].Value() != 0x40070 || !strings.HasPrefix(got[0].Owner, "Wrapper~") {
		t.Fatalf("%+v %v", got, err)
	}
	// Liberation is a flag, not a reason to rewrite the owner to the child name.
	m.References[1].Integrate = "hidden"
	if got, err := planTestOwners([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateInstalled}}); err == nil || got != nil {
		t.Fatal("conflicting integration did not fail atomically", got, err)
	}
}

func TestCBSOwnerIntentRejectsUnsupportedOrAmbiguousGraph(t *testing.T) {
	for _, body := range []string{
		`<update name="a"><applicable disposition="detect"><detectUpdate><update name="b"/></detectUpdate></applicable>` + ownerChild + `</update><update name="b"><applicable disposition="detect"><detectUpdate><update name="a"/></detectUpdate></applicable></update>`,
		`<update name="a"><applicable disposition="detect"><detectUpdate><update name="missing"/></detectUpdate></applicable>` + ownerChild + `</update>`,
		`<update name="a"><applicable disposition="detect"><detectUpdate xmlns="urn:foreign"><parent name="x"/></detectUpdate></applicable>` + ownerChild + `</update>`,
		`<update name="a"><applicable disposition="staged"><updateComponent/></applicable>` + ownerChild + `</update>`,
		`<update name="a"><selectable disposition="absent"><detectNone default="false"/></selectable>` + ownerChild + `</update>`,
		`<update name="a">` + ownerChild + `</update><update name="A"/>`,
	} {
		m := cbsIntentManifest(t, "Package", "neutral", body)
		if got, err := planTestOwners([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateInstalled}}); err == nil || got != nil {
			t.Fatal("accepted invalid graph", body, got, err)
		}
	}
	m := cbsIntentManifest(t, "Package", "neutral", `<update name="a">`+ownerChild+`</update>`)
	input := CBSPackageIntent{Manifest: m, IntendedState: CBSStateInstalled, Parents: []AssemblyIdentity{{Name: "missing"}}}
	if _, err := planTestOwners([]CBSPackageIntent{input}); err == nil {
		t.Fatal("accepted unresolved parent")
	}
	input.Parents = nil
	input.IntendedState = 0x80
	if _, err := planTestOwners([]CBSPackageIntent{input}); err == nil {
		t.Fatal("inferred permanent owner state")
	}
}

// The target inventory is explicit: native package declarations may name many
// inapplicable editions or languages which must never become owner records.
func planTestOwners(inputs []CBSPackageIntent) ([]CBSPackageOwnerIntent, error) {
	var targets []AssemblyIdentity
	for _, p := range inputs {
		for _, r := range p.Manifest.References {
			if r.Kind == "package" {
				targets = append(targets, r.Identity)
			}
		}
	}
	seen := map[string]bool{}
	for _, p := range inputs {
		seen[p.Manifest.Identity.ExactKey()] = true
	}
	contexts := append([]CBSPackageIntent(nil), inputs...)
	for _, target := range targets {
		if !seen[target.ExactKey()] {
			seen[target.ExactKey()] = true
			contexts = append(contexts, CBSPackageIntent{Manifest: &AssemblyManifest{Identity: target, Package: &AssemblyPackage{}}, IntendedState: CBSStateStaged})
		}
	}
	return PlanCBSPackageOwners(contexts, targets)
}

func TestCBSOwnerIntentDoesNotSelectTargets(t *testing.T) {
	m := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="x">`+ownerChild+`</update>`)
	owners, err := PlanCBSPackageOwners([]CBSPackageIntent{{Manifest: m, IntendedState: CBSStateInstalled}}, nil)
	if err != nil || len(owners) != 0 {
		t.Fatal("reference presence selected a target", owners, err)
	}
}

func TestCBSOwnerIntentRepeatedDetectorsAreConjunctive(t *testing.T) {
	parent := cbsIntentManifest(t, "Parent", "neutral", `<update name="a"/><update name="b"><selectable disposition="staged"><detectNone default="false"/></selectable></update>`)
	wrapper := cbsIntentManifest(t, "MonthlyBundles-Wrapper", "neutral", `<update name="Content"><applicable disposition="staged"><detectUpdate><parent name="a"/></detectUpdate><detectUpdate><parent name="b"/></detectUpdate></applicable>`+ownerChild+`</update>`)
	inputs := []CBSPackageIntent{{Manifest: parent, IntendedState: CBSStateInstalled}, {Manifest: wrapper, IntendedState: CBSStateInstalled, Parents: []AssemblyIdentity{parent.Identity}}}
	owners, err := planTestOwners(inputs)
	if err != nil || len(owners) != 1 || owners[0].State != CBSStateStaged {
		t.Fatalf("one true detector incorrectly enabled update: %+v %v", owners, err)
	}
	inputs[0].SelectableChoices = map[string]bool{"b": true}
	owners, err = planTestOwners(inputs)
	if err != nil || len(owners) != 1 || owners[0].State != CBSStateInstalled {
		t.Fatalf("all true detectors lost update: %+v %v", owners, err)
	}
}

func TestCBSOwnerIntentProductProjection(t *testing.T) {
	// Native AddPackage checks both integration=4 and child releaseType=18.
	// Neither the wrapper release type nor ordinary liberation suffices.
	for _, integration := range []string{"visible", "hidden", "liberate"} {
		for _, product := range []bool{false, true} {
			m := cbsIntentManifest(t, "Edition-Wrapper", "neutral", `<update name="Edition">`+strings.Replace(ownerChild, `integrate="hidden"`, `integrate="`+integration+`"`, 1)+`</update>`)
			m.Package.Attributes = []ManifestAttribute{{Name: "releaseType", Value: "Product"}}
			target := &AssemblyManifest{Identity: m.References[0].Identity, Package: &AssemblyPackage{}}
			if product {
				target.Package.Attributes = []ManifestAttribute{{Name: "releaseType", Value: "Product"}}
			}
			for _, state := range []uint32{CBSStateStaged, CBSStateInstalled} {
				inputs := []CBSPackageIntent{{Manifest: m, IntendedState: state}, {Manifest: target, IntendedState: CBSStateInstalled}}
				owners, err := PlanCBSPackageOwners(inputs, []AssemblyIdentity{target.Identity})
				wantOwner, _ := cbsPackageName(m.Identity)
				if product && integration == "liberate" {
					wantOwner, _ = cbsPackageName(target.Identity)
				}
				flag := map[string]uint32{"visible": 2, "hidden": 3, "liberate": 4}[integration]
				if err != nil || len(owners) != 1 || owners[0].Owner != wantOwner || owners[0].Value() != flag<<16|state {
					t.Fatalf("integration=%s product=%v state=%x: owners=%+v err=%v", integration, product, state, owners, err)
				}
				if _, err := PlanCBSPackageOwners(inputs[:1], []AssemblyIdentity{target.Identity}); err == nil {
					t.Fatal("accepted target without metadata")
				}
			}
		}
	}
}
