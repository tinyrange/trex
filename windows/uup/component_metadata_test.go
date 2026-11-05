package uup

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestComponentMetadataExactUnselectedIdentity(t *testing.T) {
	// This native identity is deliberately not admitted by any package plan.
	const stem = "amd64_microsoft-windows-kernel32_31bf3856ad364e35_10.0.26100.9444_none_2f8379ba064efb69"
	const identity = "Microsoft-Windows-Kernel32, Culture=neutral, Version=10.0.26100.9444, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS"
	const xml = `<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Microsoft-Windows-Kernel32" language="neutral" version="10.0.26100.9444" publicKeyToken="31bf3856ad364e35" processorArchitecture="amd64" versionScope="nonSxS"/></assembly>`
	entries := []stageMetadataEntry{
		{Name: stem + ".manifest", Path: "metadata/" + stem + ".manifest"},
		{Name: "payload.manifest", Path: stem + "/payload.manifest"},
	}
	reads, releases := 0, 0
	text := xml
	index, err := newComponentMetadataIndex(entries, func(name string) (storage.Reader, error) {
		reads++
		if name != entries[0].Path {
			t.Fatalf("opened payload manifest: %s", name)
		}
		return &starfile.Bytes{Name: name, Data: []byte(text)}, nil
	}, func(string) { releases++ })
	if err != nil || reads != 0 {
		t.Fatalf("eager read: %d %v", reads, err)
	}
	file, found, err := index.Open([]byte(identity))
	if err != nil || !found || file == nil || reads != 1 || releases != 1 {
		t.Fatalf("exact read: %v %v reads=%d releases=%d", found, err, reads, releases)
	}
	snapshot := file.(*ParsedAssemblyFile)
	ids := [][]byte{[]byte(identity)}
	reused, err := index.PlanComponentsWithManifests(ids, []*ParsedAssemblyFile{snapshot})
	if err != nil || len(reused) != 1 || reused[0].preparedManifest != snapshot || reads != 1 || releases != 1 {
		t.Fatalf("reuse did not preserve validated snapshot: %+v %v reads=%d", reused, err, reads)
	}
	foreign, err := newComponentMetadataIndex(entries, index.open, index.release)
	if err != nil {
		t.Fatal(err)
	}
	// Equal bytes from another stage/index do not prove this index's binding.
	if value, err := foreign.PlanComponentsWithManifests(ids, []*ParsedAssemblyFile{snapshot}); err == nil || value != nil {
		t.Fatal("accepted foreign-index snapshot")
	}
	unbound, err := parseAssemblyFile(&starfile.Bytes{Data: []byte(xml)})
	if err != nil {
		t.Fatal(err)
	}
	for _, files := range [][]*ParsedAssemblyFile{{}, {nil}, {unbound}, {snapshot, snapshot}} {
		if value, err := index.PlanComponentsWithManifests(ids, files); err == nil || value != nil {
			t.Fatal("accepted unbound/mismatched snapshots")
		}
	}
	for _, bad := range []string{"invalid", strings.Replace(identity, "Culture=neutral", "Culture=*", 1), strings.Replace(identity, "10.0.26100.9444", "10.0.26100.1", 1)} {
		if value, err := index.PlanComponentsWithManifests([][]byte{[]byte(bad)}, []*ParsedAssemblyFile{snapshot}); err == nil || value != nil {
			t.Fatal("snapshot bypassed exact identity")
		}
	}
	if value, err := index.PlanComponentsWithManifests([][]byte{[]byte(identity), []byte(strings.ToLower(identity))}, []*ParsedAssemblyFile{snapshot, snapshot}); err == nil || value != nil {
		t.Fatal("snapshot bypassed duplicate rejection")
	}
	text = "corrupt replacement"
	if value, err := index.PlanComponentsWithManifests(ids, []*ParsedAssemblyFile{snapshot}); err != nil || value[0].preparedManifest != snapshot || reads != 1 {
		t.Fatal("reuse reopened source instead of using snapshot")
	}
	text = xml
	// Neither alternate CSI type/scope nor another version may use a readable
	// basename match. The requested identity must select the matching hash.
	for _, other := range []string{
		strings.Replace(identity, "10.0.26100.9444", "10.0.26100.1", 1),
		strings.Replace(identity, ", versionScope=nonSxS", "", 1),
		strings.Replace(identity, ", Version=", ", Type=dualModeDriver, Version=", 1),
	} {
		if file, found, err := index.Open([]byte(other)); err != nil || found || file != nil {
			t.Fatalf("foreign match: %s %v %v", other, found, err)
		}
	}
	if reads != 1 {
		t.Fatal("foreign identity read an unrelated manifest")
	}
	for _, bad := range []string{"../manifest", strings.Replace(identity, "Culture=neutral", "Culture=*", 1)} {
		if _, _, err := index.Open([]byte(bad)); err == nil {
			t.Fatalf("accepted selector %q", bad)
		}
	}
	// A matching transport name cannot conceal a foreign decoded identity.
	text = strings.Replace(xml, "nonSxS", "SxS", 1)
	if file, found, err := index.Open([]byte(identity)); err == nil || found || file != nil {
		t.Fatal("corrupt metadata treated as missing or accepted")
	}
	if releases != 2 {
		t.Fatal("failed read did not release decoder cache")
	}
	text = strings.Replace(xml, "</assembly>", "<package/></assembly>", 1)
	if _, _, err := index.Open([]byte(identity)); err == nil {
		t.Fatal("accepted package as component")
	}
	text = xml
	plan, err := index.PlanComponents([][]byte{[]byte(identity)})
	if err != nil || len(plan) != 1 || plan[0].Path != entries[0].Path || plan[0].Stem != stem || !plan[0].StagedOnly || plan[0].PreviousStem != "" {
		t.Fatalf("exact staging plan: %+v %v", plan, err)
	}
	// Effect/CSI consumers must observe the same validated byte snapshot,
	// without reopening an evicted compressed archive member.
	beforeReads := reads
	text = "corrupt later source"
	records, err := planCSIComponentDescriptions(plan, index.open, index.release)
	if err != nil || len(records) != 1 || records[0].ManifestSHA256 != sha256.Sum256([]byte(xml)) || reads != beforeReads {
		t.Fatalf("snapshot descriptions: %+v %v reads=%d", records, err, reads)
	}
	changed := plan[0]
	changed.Identity.Name = "foreign"
	if _, err := planCSIComponentDescriptions([]PlannedComponent{changed}, index.open, index.release); err == nil {
		t.Fatal("snapshot bypassed identity verification")
	}
	changed = plan[0]
	changed.Path = "changed"
	if _, err := openPlannedManifest(changed, func(name string) (storage.Reader, error) {
		if name != "changed" {
			t.Fatal(name)
		}
		return nil, fmt.Errorf("new path unavailable")
	}, nil); err == nil {
		t.Fatal("path change retained stale snapshot")
	}
	text = xml
	for _, identities := range [][][]byte{
		{[]byte(identity), []byte(strings.ToLower(identity))},
		{[]byte(identity), []byte(strings.Replace(identity, "10.0.26100.9444", "10.0.26100.1", 1))},
		{[]byte(identity), []byte("invalid")},
	} {
		if partial, err := index.PlanComponents(identities); err == nil || partial != nil {
			t.Fatalf("staging accepted partial/duplicate request: %+v %v", partial, err)
		}
	}
}

func TestComponentMetadataRejectsDuplicateAndMalformedInventory(t *testing.T) {
	const name = "amd64_a_31bf3856ad364e35_10.0.1.0_none_0000000000000000.manifest"
	noRead := func(string) (storage.Reader, error) { return nil, fmt.Errorf("unexpected read") }
	_, err := newComponentMetadataIndex([]stageMetadataEntry{{Name: name, Path: "a/" + name}, {Name: name, Path: "b/" + name}}, noRead, nil)
	if err == nil {
		t.Fatal("accepted ambiguous metadata")
	}
	_, err = newComponentMetadataIndex([]stageMetadataEntry{{Name: "bad.manifest", Path: "bad.manifest"}}, noRead, nil)
	if err == nil {
		t.Fatal("accepted malformed metadata path")
	}
	if _, err := NewComponentMetadataIndex(nil); err == nil {
		t.Fatal("accepted nil stage")
	}
}
