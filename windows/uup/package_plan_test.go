package uup

import (
	"fmt"
	"strings"
	"testing"
)

func TestPackageDriverReferenceSelectsDualModeAssembly(t *testing.T) {
	state, err := newAssemblyImageState([]string{"package~token~amd64~~1.0.mum"}, []string{"amd64_dual_input.inf_token_1.0_none_old.manifest"})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="package" version="2.0" processorArchitecture="amd64" publicKeyToken="token" language="neutral"/><package><update><driver><assemblyIdentity name="dual_input.inf" version="2.0" processorArchitecture="amd64" publicKeyToken="token" language="neutral" type="dualModeDriver"/></driver></update></package></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.References) != 1 || manifest.References[0].Kind != "driver" {
		t.Fatalf("driver reference not parsed: %#v", manifest.References)
	}
	pack, driver := manifest.Identity, manifest.References[0].Identity
	packagePath := manifestPath{Path: "package.mum", Identity: pack}
	driverPath := manifestPath{Path: "driver.manifest", Identity: driver, Component: ComponentPathIdentity{Identity: driver, Stem: "new-driver"}}
	catalog := &stageManifestCatalog{
		stage:            &CumulativeStage{},
		packagesByStable: map[string][]manifestPath{pack.StableKey(): {packagePath}},
		parsedPackages:   map[string]*AssemblyManifest{"package.mum": manifest},
		componentsByName: map[string][]manifestPath{componentCanonicalKey(driver): {driverPath}},
		parsedComponents: map[string]*AssemblyManifest{"driver.manifest": {Identity: driver}},
	}
	plan, err := catalog.plan(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Components) != 1 || plan.Components[0].Identity.ExactKey() != driver.ExactKey() {
		t.Fatalf("package driver omitted: %#v", plan.Components)
	}
	if !strings.Contains(plan.Components[0].SelectedBy, "via driver") {
		t.Fatalf("driver provenance lost: %q", plan.Components[0].SelectedBy)
	}
}

func TestSelectedDeploymentInstallsNewComponentFamily(t *testing.T) {
	for _, dependencyType := range []string{"install", ""} {
		t.Run("type="+dependencyType, func(t *testing.T) {
			state, err := newAssemblyImageState([]string{"package~token~amd64~~1.0.mum"}, []string{"amd64_deployment_token_1.0_none_hash.manifest"})
			if err != nil {
				t.Fatal(err)
			}
			identity := func(name string) AssemblyIdentity {
				return AssemblyIdentity{Name: name, Version: "2.0", ProcessorArchitecture: "amd64", PublicKeyToken: "token", Language: "neutral"}
			}
			pack, deployment, policy := identity("package"), identity("deployment"), identity("new-policy")
			optional, orphan, missing := identity("optional"), identity("orphan"), identity("missing-feature")
			dependency := func(id AssemblyIdentity) AssemblyReference {
				return AssemblyReference{Kind: "dependentAssembly", DependencyType: dependencyType, Identity: id}
			}
			packagePath := manifestPath{Path: "package.mum", Identity: pack}
			catalog := &stageManifestCatalog{
				stage:            &CumulativeStage{},
				packagesByStable: map[string][]manifestPath{pack.StableKey(): {packagePath}},
				parsedPackages: map[string]*AssemblyManifest{"package.mum": {
					Identity: pack, References: []AssemblyReference{{Kind: "component", Identity: deployment}},
				}},
				componentsByName: make(map[string][]manifestPath),
				parsedComponents: make(map[string]*AssemblyManifest),
			}
			for _, manifest := range []*AssemblyManifest{
				{Identity: deployment, References: []AssemblyReference{dependency(policy), dependency(optional)}},
				{Identity: policy},
				{Identity: optional, References: []AssemblyReference{dependency(orphan), {Kind: "dependentAssembly", DependencyType: "prerequisite", Identity: missing}}},
				{Identity: orphan},
			} {
				id := manifest.Identity
				candidate := manifestPath{Path: id.Name + ".manifest", Identity: id, Component: ComponentPathIdentity{Identity: id, Stem: id.Name}}
				catalog.componentsByName[componentCanonicalKey(id)] = []manifestPath{candidate}
				catalog.parsedComponents[strings.ToLower(candidate.Path)] = manifest
			}
			plan, err := catalog.plan(state)
			if err != nil {
				t.Fatal(err)
			}
			got := make(map[string]PlannedComponent)
			for _, component := range plan.Components {
				got[component.Identity.Name] = component
			}
			if len(got) != 2 || got[policy.Name].Identity.Name != policy.Name || got[deployment.Name].Identity.Name != deployment.Name {
				t.Fatalf("selected deployment must install its new policy, but not an inapplicable optional branch: %#v", got)
			}
			if !state.hasInstalledComponent(policy) {
				t.Fatal("new policy was not made available to following stages")
			}
			if !strings.Contains(got[policy.Name].SelectedBy, deployment.Name) {
				t.Fatalf("new policy lost its install-edge provenance: %q", got[policy.Name].SelectedBy)
			}
		})
	}
}

func TestContainedPackageApplicabilityUsesInstalledFamily(t *testing.T) {
	state, err := newAssemblyImageState([]string{
		"Microsoft-Windows-Editions-Professional-Package~31bf3856ad364e35~amd64~en-US~10.0.26100.1.mum",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	professional := AssemblyIdentity{
		Name: "Microsoft-Windows-Editions-Professional-Package", PublicKeyToken: "31bf3856ad364e35",
		ProcessorArchitecture: "amd64", Language: "en-US", Version: "10.0.26100.1742",
	}
	enterpriseG := professional
	enterpriseG.Name = "Microsoft-Windows-Editions-EnterpriseG-Package"
	if !state.hasInstalledPackageFamily(professional) {
		t.Fatal("installed Professional child was not applicable")
	}
	if state.hasInstalledPackageFamily(enterpriseG) {
		t.Fatal("absent EnterpriseG child was applicable")
	}
}

func TestCBSPackageStateInstalled(t *testing.T) {
	for _, state := range []uint32{0x50, 0x60, 0x70, 0x80} {
		if !cbsPackageStateInstalled(state) {
			t.Fatalf("state %#x was not installed", state)
		}
	}
	for _, state := range []uint32{0, 0x10, 0x20, 0x30, 0x40, 0x51, 0x90} {
		if cbsPackageStateInstalled(state) {
			t.Fatalf("state %#x was installed", state)
		}
	}
}

func TestPackageManifestApplicabilityUsesParentClauses(t *testing.T) {
	state, err := newAssemblyImageState([]string{
		"Microsoft-Windows-Editions-Professional-Package~31bf3856ad364e35~amd64~~10.0.26100.1.mum",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	identity := func(name string) AssemblyIdentity {
		return AssemblyIdentity{Name: name, PublicKeyToken: "31bf3856ad364e35", ProcessorArchitecture: "amd64", Language: "neutral", Version: "10.0.26100.1"}
	}
	professional := &AssemblyManifest{References: []AssemblyReference{{Kind: "parent", Identity: identity("Microsoft-Windows-Editions-Professional-Package")}}}
	enterpriseG := &AssemblyManifest{References: []AssemblyReference{{Kind: "parent", Identity: identity("Microsoft-Windows-Editions-EnterpriseG-Package")}}}
	newRoot := identity("Package_for_ServicingStack")
	newChild := &AssemblyManifest{References: []AssemblyReference{{Kind: "parent", Identity: newRoot}}}
	if !packageManifestApplicable(professional, state, nil) {
		t.Fatal("installed parent did not make child applicable")
	}
	if packageManifestApplicable(enterpriseG, state, nil) {
		t.Fatal("absent SKU parent made child applicable")
	}
	if !packageManifestApplicable(newChild, state, map[string]struct{}{newRoot.ExactKey(): {}}) {
		t.Fatal("selected stage parent did not make new child applicable")
	}
	if !packageManifestApplicable(&AssemblyManifest{}, state, nil) {
		t.Fatal("unconditional child was not applicable")
	}
}

func TestWildcardResourceReferenceRecognizesBothWrappers(t *testing.T) {
	for _, reference := range []AssemblyReference{
		{Kind: "dependentAssembly", ResourceType: "Resources", Identity: AssemblyIdentity{Name: "component.resources", Language: "*"}},
		{Kind: "component", Identity: AssemblyIdentity{Name: "Microsoft.Windows.Common-Controls.Resources", Language: "*"}},
	} {
		if !isWildcardResourceReference(reference) {
			t.Fatalf("reference was not recognized: %#v", reference)
		}
	}
	if isWildcardResourceReference(AssemblyReference{Kind: "component", Identity: AssemblyIdentity{Name: "component.Resources", Language: "en-US"}}) {
		t.Fatal("concrete resource identity was treated as a wildcard")
	}
}

func TestComponentPrerequisiteFiltersOwnerAndOrphanedDependencies(t *testing.T) {
	identity := func(name string) AssemblyIdentity {
		return AssemblyIdentity{Name: name, PublicKeyToken: "token", ProcessorArchitecture: "amd64", Language: "neutral", Version: "1.0"}
	}
	a, b, prerequisite := identity("a"), identity("b"), identity("prerequisite")
	roots := map[string]struct{}{a.ExactKey(): {}}
	dependencies := map[string][]string{a.ExactKey(): {b.ExactKey()}}
	prerequisites := map[string][]AssemblyIdentity{a.ExactKey(): {prerequisite}}
	selected := map[string]AssemblyIdentity{a.ExactKey(): a, b.ExactKey(): b}
	empty, err := newAssemblyImageState(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolveApplicableComponents(roots, dependencies, prerequisites, selected, empty); len(got) != 0 {
		t.Fatalf("inapplicable closure = %#v", got)
	}
	installed, err := newAssemblyImageState(nil, []string{"amd64_prerequisite_token_1.0_none_hash.manifest"})
	if err != nil {
		t.Fatal(err)
	}
	got := resolveApplicableComponents(roots, dependencies, prerequisites, selected, installed)
	if len(got) != 2 {
		t.Fatalf("applicable closure = %#v", got)
	}
}

func TestComponentPrerequisiteInvalidationIsTransitive(t *testing.T) {
	identity := func(name string) AssemblyIdentity {
		return AssemblyIdentity{Name: name, PublicKeyToken: "token", ProcessorArchitecture: "amd64", Language: "neutral", Version: "1.0"}
	}
	a, b, missing := identity("a"), identity("b"), identity("missing")
	selected := map[string]AssemblyIdentity{a.ExactKey(): a, b.ExactKey(): b}
	prerequisites := map[string][]AssemblyIdentity{
		a.ExactKey(): {b},
		b.ExactKey(): {missing},
	}
	state, err := newAssemblyImageState(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := resolveApplicableComponents(map[string]struct{}{a.ExactKey(): {}}, nil, prerequisites, selected, state)
	if len(got) != 0 {
		t.Fatalf("transitively inapplicable closure = %#v", got)
	}
}

func TestComponentWildcardPrerequisiteAcceptsAnySelectedProvider(t *testing.T) {
	provider := AssemblyIdentity{Name: "resource", PublicKeyToken: "token", ProcessorArchitecture: "amd64", Language: "en-US", Version: "1.0"}
	owner := provider
	owner.Name, owner.Language = "owner", "neutral"
	wildcard := provider
	wildcard.Language = "*"
	selected := map[string]AssemblyIdentity{owner.ExactKey(): owner, provider.ExactKey(): provider}
	state, err := newAssemblyImageState(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := resolveApplicableComponents(
		map[string]struct{}{owner.ExactKey(): {}},
		map[string][]string{owner.ExactKey(): {provider.ExactKey()}},
		map[string][]AssemblyIdentity{owner.ExactKey(): {wildcard}},
		selected,
		state,
	)
	if len(got) != 2 {
		t.Fatalf("wildcard-applicable closure = %#v", got)
	}
}

func TestInstalledComponentIndexUsesCanonicalAndAbbreviatedPaths(t *testing.T) {
	state, err := newAssemblyImageState(nil, []string{
		"amd64_microsoft-windows-wdf-usermodelibrary_31bf3856ad364e35_10.0.26100.1591_none_f4a95a899b0cfa49.manifest",
		"amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_5.82.26100.1591_uz-..-uz_0fbfb1c9f2926e3e.manifest",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range []AssemblyIdentity{
		{Name: "Microsoft-Windows-WDF-Usermode Library", Version: "10.0.26100.1591", ProcessorArchitecture: "amd64", Language: "neutral", PublicKeyToken: "31bf3856ad364e35"},
		{Name: "Microsoft.Windows.Common-Controls.Resources", Version: "5.82.26100.1591", ProcessorArchitecture: "amd64", Language: "uz-Latn-UZ", PublicKeyToken: "6595b64144ccf1df"},
	} {
		if !state.hasInstalledComponent(identity) {
			t.Fatalf("installed component was not found: %#v", identity)
		}
	}
}

func TestInstalledComponentFamilyIgnoresVersionButPreservesLanguage(t *testing.T) {
	state, err := newAssemblyImageState(nil, []string{
		"amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_5.82.26100.1_en-us_hash.manifest",
	})
	if err != nil {
		t.Fatal(err)
	}
	wanted := AssemblyIdentity{
		Name: "Microsoft.Windows.Common-Controls.Resources", Version: "5.82.26100.1591",
		ProcessorArchitecture: "amd64", Language: "en-US", PublicKeyToken: "6595b64144ccf1df",
	}
	if !state.hasInstalledComponentFamily(wanted) {
		t.Fatal("installed abbreviated family was not found across versions")
	}
	previous, found := state.latestInstalledComponent(wanted)
	if !found || previous.Component.Stem != "amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_5.82.26100.1_en-us_hash" {
		t.Fatalf("latest installed component = %#v, found=%t", previous, found)
	}
	wanted.Language = "af-ZA"
	if state.hasInstalledComponentFamily(wanted) {
		t.Fatal("absent language was accepted as an installed component family")
	}
}

func BenchmarkHasInstalledComponentIndexed(b *testing.B) {
	names := make([]string, 20000)
	for index := range names {
		names[index] = fmt.Sprintf("amd64_component-%05d_token_1.0_none_hash.manifest", index)
	}
	state, err := newAssemblyImageState(nil, names)
	if err != nil {
		b.Fatal(err)
	}
	wanted := AssemblyIdentity{Name: "component-19999", Version: "1.0", ProcessorArchitecture: "amd64", Language: "neutral", PublicKeyToken: "token"}
	b.ResetTimer()
	for range b.N {
		if !state.hasInstalledComponent(wanted) {
			b.Fatal("component not found")
		}
	}
}

func BenchmarkResolveApplicableComponentsLinear(b *testing.B) {
	const count = 20000
	identities := make([]AssemblyIdentity, count)
	selected := make(map[string]AssemblyIdentity, count)
	prerequisites := make(map[string][]AssemblyIdentity, count)
	for index := range identities {
		identities[index] = AssemblyIdentity{Name: fmt.Sprintf("component-%05d", index), Version: "1.0", ProcessorArchitecture: "amd64", Language: "neutral", PublicKeyToken: "token"}
		selected[identities[index].ExactKey()] = identities[index]
		if index != 0 {
			prerequisites[identities[index].ExactKey()] = []AssemblyIdentity{identities[index-1]}
		}
	}
	missing := AssemblyIdentity{Name: "missing", Version: "1.0", ProcessorArchitecture: "amd64", Language: "neutral", PublicKeyToken: "token"}
	prerequisites[identities[0].ExactKey()] = []AssemblyIdentity{missing}
	state, err := newAssemblyImageState(nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	root := map[string]struct{}{identities[count-1].ExactKey(): {}}
	b.ResetTimer()
	for range b.N {
		if got := resolveApplicableComponents(root, nil, prerequisites, selected, state); len(got) != 0 {
			b.Fatalf("inapplicable chain retained %d components", len(got))
		}
	}
}
