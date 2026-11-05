package uup

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestCBSDeploymentSourceTwoLengths(t *testing.T) {
	text := "Package_11_for_KB5126052~31bf3856ad364e35~amd64~~10.0.9347.1.5126052-721_neutral"
	for _, extra := range []string{"", "8", "9"} {
		data := make([]byte, 8+len(text)+len(extra))
		binary.LittleEndian.PutUint32(data, uint32(len(text)))
		binary.LittleEndian.PutUint32(data[4:], uint32(len(extra)))
		copy(data[8:], text+extra)
		got, err := parseCBSDeploymentSource(data)
		if err != nil || got.Update != "5126052-721_neutral" || got.Package.Version != "10.0.9347.1" {
			t.Fatalf("%+v %v", got, err)
		}
		for _, bad := range [][]byte{data[:7], data[:len(data)-1], append(append([]byte{}, data...), 0)} {
			if _, err := parseCBSDeploymentSource(bad); err == nil {
				t.Fatal("accepted bad length")
			}
		}
		binary.LittleEndian.PutUint32(data, 0xffffffff)
		if _, err := parseCBSDeploymentSource(data); err == nil {
			t.Fatal("accepted overflowing length")
		}
	}
}

func TestActivationSeparatesStagedRootsAndSharedDependencies(t *testing.T) {
	all := map[string]struct{}{"active": {}, "staged": {}, "shared": {}, "private": {}, "new": {}}
	dependencies := map[string][]string{"active": {"shared", "new"}, "staged": {"shared", "private"}, "shared": {"active"}, "new": {"inapplicable"}}
	got := activeComponentClosure(map[string]struct{}{"active": {}, "inapplicable": {}}, dependencies, all)
	if len(got) != 3 {
		t.Fatal(got)
	}
	for _, name := range []string{"active", "shared", "new"} {
		if _, ok := got[name]; !ok {
			t.Fatal("lost active dependency", name)
		}
	}
	for _, name := range []string{"staged", "private", "inapplicable"} {
		if _, ok := got[name]; ok {
			t.Fatal("activated optional branch", name)
		}
	}
}

func TestDeploymentActivationUsesExistingStateAndNewUpdatePredicates(t *testing.T) {
	id := AssemblyIdentity{Name: "IIS-Deployment", ProcessorArchitecture: "amd64", PublicKeyToken: "token", Version: "10.0.26100.9711"}
	activation := &deploymentActivation{deployments: map[string]bool{id.StableKey(): false}, updates: map[string]bool{"enabled": true}}
	manifest, err := ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="package" version="1.0"/><package><update name="feature"><applicable disposition="detect"><detectUpdate><parent name="enabled"/></detectUpdate></applicable><component><assemblyIdentity name="deployment" version="1.0"/></component></update></package></assembly>`))
	if err != nil {
		t.Fatal(err)
	}
	ref := manifest.References[0]
	if active, err := activation.rootActive(manifest, ref, id); err != nil || active {
		t.Fatal("existing staged feature activated", active, err)
	}
	id.Name = "new-deployment"
	if active, err := activation.rootActive(manifest, ref, id); err != nil || !active {
		t.Fatal("new deployment of enabled update lost", active, err)
	}
	activation.updates["enabled"] = false
	if active, err := activation.rootActive(manifest, ref, id); err != nil || active {
		t.Fatal("disabled parent activated", active, err)
	}
	manifest.PackageUpdates[0].Conditions[0].Name = "unknownCondition"
	if _, err := activation.rootActive(manifest, ref, id); err == nil {
		t.Fatal("unknown condition accepted")
	}
	manifest.PackageUpdates[0].Conditions = nil
	if active, err := activation.rootActive(manifest, ref, id); err != nil || !active {
		t.Fatal("unconditional new root lost", active, err)
	}
}
