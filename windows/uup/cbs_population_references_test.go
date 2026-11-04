package uup

import "testing"

func TestCBSOrdinaryPopulationLiberatedProductAndScopedReferences(t *testing.T) {
	parent := cbsIntentManifest(t, "Wrapper", "neutral", `<update name="f"/>`)
	product := cbsIntentManifest(t, "Product", "neutral", "")
	ordinary := cbsIntentManifest(t, "Ordinary", "neutral", "")
	product.Package.Attributes = append(product.Package.Attributes, ManifestAttribute{Name: "releaseType", Value: "Product"})
	parent.References = []AssemblyReference{
		{Kind: "package", Identity: product.Identity, UpdateName: "F", Integrate: "liberate"},
		{Kind: "package", Identity: ordinary.Identity, UpdateName: "f", Integrate: "liberate"},
	}
	index, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: parent}, {Manifest: product}, {Manifest: ordinary}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := PlanCBSOrdinaryPopulation(index, nil, []CBSOrdinaryRequest{populationRequest(t, parent, 0x70)}, populationPolicy())
	if err != nil {
		t.Fatal(err)
	}
	self, _ := cbsPackageName(product.Identity)
	wrapper, _ := cbsPackageName(parent.Identity)
	if result.Executions[1].Owners[0].Owner != self || result.Executions[2].Owners[0].Owner != wrapper || result.Executions[1].Owners[0].Integration != 4 {
		t.Fatal(result.Executions)
	}
	bad := cbsIntentManifest(t, "Malformed", "neutral", `<update name="f"/>`)
	bad.References = []AssemblyReference{{Kind: "package", Identity: ordinary.Identity, UpdateName: "nonexistent"}}
	malformed, err := NewCBSUpdateStateIndex([]CBSPackageIntent{{Manifest: bad}, {Manifest: ordinary}})
	if err != nil {
		t.Fatal(err)
	}
	if p, err := PlanCBSOrdinaryPopulation(malformed, nil, []CBSOrdinaryRequest{populationRequest(t, bad, 0x70)}, populationPolicy()); err == nil || p != nil {
		t.Fatal("unscoped reference silently dropped", p, err)
	}
}
