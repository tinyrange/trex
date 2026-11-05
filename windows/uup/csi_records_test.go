package uup

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestCSIComponentStateUsesDecodedBytesAndResidentOwners(t *testing.T) {
	const text = "HyperV-Compute-EventLog, Culture=neutral, Version=10.0.26100.8328, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=NonSxS"
	id, err := parseCSIIdentity([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	component := PlannedComponent{Identity: id, Stem: "amd64_hyperv-compute-eventlog_31bf3856ad364e35_10.0.26100.8328_none_7ba4854d722b50c1", Path: "input.manifest", StagedOnly: true}
	const xml = `<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="HyperV-Compute-EventLog" version="10.0.26100.8328" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="NonSxS"/><file name="1394.inf_loc"/><file name="wpcip.inf"/></assembly>`
	residentID, err := parseCSIIdentity([]byte("Microsoft-Windows-IIS-ClientCertificateMappingAuthentication, Culture=neutral, Version=10.0.26100.7920, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=NonSxS"))
	if err != nil {
		t.Fatal(err)
	}
	resident := PlannedComponent{Identity: residentID, Stem: "amd64_microsoft-windows-iis-clientcertificatemappingauthentication_31bf3856ad364e35_10.0.26100.7920_none_5a73d8108218d44a"}
	plan := StageAssemblyPlan{Components: []PlannedComponent{component}, Deployments: []DeploymentOwnership{{Identity: id, Components: []PlannedComponent{component, resident}}}}
	opens, releases := 0, 0
	open := func(path string) (storage.Reader, error) {
		opens++
		if path != component.Path {
			t.Fatalf("resident content was rewritten: %s", path)
		}
		return &starfile.Bytes{Name: path, Data: []byte(xml)}, nil
	}
	result, err := planCSIComponentState(plan, open, func(string) { releases++ })
	if err != nil {
		t.Fatal(err)
	}
	if opens != 1 || releases != 1 || len(result.Components) != 1 || len(result.Owners) != 2 {
		t.Fatalf("result=%+v opens=%d releases=%d", result, opens, releases)
	}
	record := result.Components[0]
	if string(record.Identity) != text || record.ManifestSHA256 != sha256.Sum256([]byte(xml)) {
		t.Fatalf("incorrect identity or decoded-manifest digest: %+v", record)
	}
	if len(record.Files) != 2 || record.Files[0].Name != "f!1394.inf_loc_c820a7a9f3fa126b" || record.Files[1].Name != "f!wpcip.inf" {
		t.Fatalf("files=%+v", record.Files)
	}
	for _, file := range record.Files {
		if file.Flags != 1 {
			t.Fatalf("invented compression/PSFX flags: %+v", file)
		}
	}
	if result.Owners[0].Name != result.Owners[1].Name || !strings.HasPrefix(result.Owners[0].Name, "c!hyperv-compute-eventlog_") {
		t.Fatalf("owners=%+v", result.Owners)
	}
	// Store descriptions deliberately do not invent owners. The full state
	// planner below must still reject a missing composition graph.
	descriptions, err := planCSIComponentDescriptions([]PlannedComponent{component}, open, nil)
	if err != nil || len(descriptions) != 1 || descriptions[0].ManifestSHA256 != record.ManifestSHA256 {
		t.Fatalf("independent descriptions: %+v %v", descriptions, err)
	}
	if _, err := planCSIComponentDescriptions([]PlannedComponent{component, component}, open, nil); err == nil {
		t.Fatal("accepted duplicate component descriptions")
	}
	// A missing closure must not silently install an unowned component.
	plan.Deployments = nil
	if _, err := planCSIComponentState(plan, open, nil); err == nil {
		t.Fatal("accepted absent ownership")
	}
	// ExactKey does not include versionScope; native identity hashes do.
	bad := component
	bad.Identity.VersionScope = ""
	plan.Components = []PlannedComponent{bad}
	if _, err := planCSIComponentState(plan, open, nil); err == nil {
		t.Fatal("accepted lossy identity equivalence")
	}
	// A malformed/repeated declared file must not alias the registry value.
	plan.Components = []PlannedComponent{component}
	if _, err := planCSIComponentState(plan, func(string) (storage.Reader, error) {
		return &starfile.Bytes{Data: []byte(strings.ReplaceAll(xml, "wpcip.inf", "1394.inf_loc"))}, nil
	}, nil); err == nil {
		t.Fatal("accepted duplicate file state")
	}
}
