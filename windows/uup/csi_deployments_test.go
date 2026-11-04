package uup

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

func TestCSIDeploymentCatalogOwnershipAndSourceFraming(t *testing.T) {
	id, err := parseCSIIdentity([]byte("0074283ce7ee52524aaa00edcf95464e, Culture=neutral, Version=4.0.15920.100, PublicKeyToken=b77a5c561934e089, ProcessorArchitecture=amd64, versionScope=NonSxS"))
	if err != nil {
		t.Fatal(err)
	}
	root := PlannedComponent{Identity: id, Stem: "amd64_0074283ce7ee52524aaa00edcf95464e_b77a5c561934e089_4.0.15920.100_none_3fb84cbf20555c08"}
	packageID := AssemblyIdentity{Name: "Package_11_for_KB5126052", PublicKeyToken: "31bf3856ad364e35", ProcessorArchitecture: "amd64", Language: "neutral", Version: "10.0.9347.1"}
	first := PlannedDeploymentSource{Package: packageID, UpdateName: "5126052-721_neutral", Deployment: id, StagedOnly: true}
	second := first
	second.UpdateName = "enabled-root"
	second.StagedOnly = false
	plan := StageAssemblyPlan{Deployments: []DeploymentOwnership{{Identity: id, Components: []PlannedComponent{root}, Sources: []PlannedDeploymentSource{first, second}}}}
	target := `<assemblyIdentity name="T"/>`
	mum := cbsIntentManifest(t, packageID.Name, "neutral", `<update name="`+first.UpdateName+`"/><update name="`+second.UpdateName+`"><applicable><updateComponent elevate="build">`+target+target+`</updateComponent></applicable></update>`)
	mum.Identity = packageID
	plan.Packages = []NamedAssemblyManifest{{Manifest: mum}}
	hash := sha256.Sum256([]byte("decoded manifest"))
	old, err := marshalCBSDeploymentSource(cbsDeploymentSource{Package: packageID, Update: first.UpdateName}, []byte("8"))
	if err != nil {
		t.Fatal(err)
	}
	name, err := csiDeploymentKey(id)
	if err != nil {
		t.Fatal(err)
	}
	sourceName, err := cbsSourceKey(string(old[8 : 8+binary.LittleEndian.Uint32(old[:4])]))
	if err != nil {
		t.Fatal(err)
	}
	p := &CSIDeploymentPlanner{hashes: map[string][32]byte{root.Stem: hash}, sources: map[string][]byte{strings.ToLower(name) + "\x00" + strings.ToLower(sourceName): old}}
	cats := map[string]csiCatalog{packageID.ExactKey(): {thumbprint: strings.Repeat("a", 64), members: map[[32]byte]bool{hash: true}}}
	result, err := p.plan(plan, CSIComponentStatePlan{}, cats)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Name != name || result[0].CatalogThumbprint != strings.Repeat("a", 64) || len(result[0].Sources) != 2 {
		t.Fatalf("%+v", result)
	}
	staged, installed := false, false
	for _, source := range result[0].Sources {
		if source.Name == sourceName {
			staged = !source.Installed
			if !bytes.Equal(source.Data, old) {
				t.Fatal("discarded opaque secondary source data")
			}
			source.Data[len(source.Data)-1] = '9'
			if old[len(old)-1] != '8' || p.sources[strings.ToLower(name)+"\x00"+strings.ToLower(sourceName)][len(old)-1] != '8' {
				t.Fatal("result aliased original source")
			}
		} else {
			installed = source.Installed
			parsed, err := ParseCBSDeploymentSource(source.Data)
			if err != nil || string(parsed.Secondary) != "9" {
				t.Fatal("new source lost native flags", parsed, err)
			}
		}
	}
	if !staged || !installed {
		t.Fatal("collapsed independent source activation")
	}
	// Failure after resolving earlier sources must not publish any predecessor
	// hashes or source records from the rejected stage.
	beforeSources, beforeHashes := len(p.sources), len(p.hashes)
	foreign := second
	foreign.Package.Name = "foreign"
	plan.Deployments[0].Sources = append(plan.Deployments[0].Sources, foreign)
	added := CSIComponentStatePlan{Components: []CSIComponentRecord{{Stem: "must-not-publish", ManifestSHA256: hash}}}
	if _, err := p.plan(plan, added, cats); err == nil {
		t.Fatal("accepted missing source catalog")
	}
	if len(p.sources) != beforeSources || len(p.hashes) != beforeHashes {
		t.Fatal("published failed stage")
	}
	plan.Deployments[0].Sources = []PlannedDeploymentSource{first}
	cats[packageID.ExactKey()] = csiCatalog{thumbprint: strings.Repeat("b", 64), members: map[[32]byte]bool{}}
	if _, err := p.plan(plan, CSIComponentStatePlan{}, cats); err == nil {
		t.Fatal("accepted unrelated catalog")
	}
}
