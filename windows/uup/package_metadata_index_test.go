package uup

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestPackageMetadataIncludesUnselectedChildrenAndValidatesIdentity(t *testing.T) {
	const suffix = "~31bf3856ad364e35~amd64~~10.0.1.0"
	xml := func(name, body string) string {
		return `<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="` + name + `" version="10.0.1.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package>` + body + `</package></assembly>`
	}
	files := map[string]string{
		"update.mum":              xml("Rollup", `<update name="optional"><package contained="false"><assemblyIdentity name="Child" version="10.0.1.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/></package></update>`),
		"Child" + suffix + ".mum": xml("Child", `<parent><assemblyIdentity name="MissingEdition" version="10.0.1.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/></parent>`),
		"Bad" + suffix + ".mum":   xml("Different", ""),
	}
	entries := []stageMetadataEntry{}
	for name := range files {
		entries = append(entries, stageMetadataEntry{Name: name, Path: name})
	}
	reads := map[string]int{}
	index, err := newPackageMetadataIndex(entries, func(name string) (storage.Reader, error) {
		reads[name]++
		text, ok := files[name]
		if !ok {
			return nil, fmt.Errorf("missing fixture %s", name)
		}
		return &starfile.Bytes{Name: name, Data: []byte(text)}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Entries()) != 3 || len(reads) != 1 {
		t.Fatalf("inventory=%v reads=%v", index.Entries(), reads)
	}
	// The raw child is available despite contained=false, an absent parent, and
	// no CIX payload. Only a later admission step may decide it is inapplicable.
	file, err := index.Open("CHILD" + suffix)
	if err != nil || file.Size() == 0 {
		t.Fatalf("unselected metadata: %v", err)
	}
	if reads["Child"+suffix+".mum"] != 1 {
		t.Fatal("reopened verified metadata")
	}
	if _, err := index.Open("Bad" + suffix); err == nil {
		t.Fatal("accepted mismatched exact identity")
	}
	if _, err := index.Open("../Child" + suffix); err == nil {
		t.Fatal("accepted arbitrary path")
	}
	copied := index.Entries()
	copied[0].Package = "mutated"
	if index.Entries()[0].Package == "mutated" {
		t.Fatal("entries alias retained index")
	}
	roots := 0
	for _, entry := range index.Entries() {
		if entry.Aggregate {
			roots++
			if entry.Package != "Rollup"+suffix {
				t.Fatal(entry)
			}
		}
	}
	if roots != 1 {
		t.Fatal("aggregate identity lost")
	}
}

func TestPackageMetadataRejectsAmbiguousAndInvalidRoots(t *testing.T) {
	const name = "P~31bf3856ad364e35~amd64~~10.0.1.0.mum"
	entries := []stageMetadataEntry{{Name: name, Path: "a/" + name}, {Name: name, Path: "b/" + name}}
	noRead := func(string) (storage.Reader, error) { t.Fatal("eager named-MUM read"); return nil, nil }
	if _, err := newPackageMetadataIndex(entries, noRead, nil); err == nil {
		t.Fatal("accepted ambiguous exact package")
	}
	for _, text := range []string{`<assembly/>`, `<assembly><assemblyIdentity name="P"/></assembly>`, `<assembly><assemblyIdentity name="P"/><package/></assembly>`} {
		_, err := newPackageMetadataIndex([]stageMetadataEntry{{Name: "update.mum", Path: "update.mum"}}, func(string) (storage.Reader, error) { return &starfile.Bytes{Data: []byte(text)}, nil }, nil)
		if err == nil {
			t.Fatal("accepted invalid aggregate", text)
		}
	}
	_, err := newPackageMetadataIndex([]stageMetadataEntry{{Name: name, Path: name}}, noRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPackageMetadataIndex(nil); err == nil || !strings.Contains(err.Error(), "stage") {
		t.Fatal(err)
	}
}
