package uup

import (
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"testing"
)

func TestPackageCatalogBoundSnapshot(t *testing.T) {
	const name = "P~31bf3856ad364e35~amd64~~10.0.1.0"
	const xml = `<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="P" version="10.0.1.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package/></assembly>`
	entries := []stageMetadataEntry{{Name: name + ".mum", Path: name + ".mum"}, {Name: name + ".cat", Path: name + ".cat"}}
	reads := 0
	source := xml
	open := func(path string) (storage.Reader, error) {
		if strings.HasSuffix(path, ".mum") {
			reads++
			return &starfile.Bytes{Data: []byte(source)}, nil
		}
		return &starfile.Bytes{Data: []byte("catalog")}, nil
	}
	index, err := newPackageMetadataIndex(entries, open, nil)
	if err != nil {
		t.Fatal(err)
	}
	file, err := index.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := file.(*ParsedAssemblyFile)
	source = "corrupt later source"
	if _, err := index.OpenCatalogWithManifest(strings.ToLower(name), snapshot); err != nil || reads != 1 {
		t.Fatalf("reopened validated MUM: %v reads=%d", err, reads)
	}
	if _, err := index.OpenCatalog(name); err == nil {
		t.Fatal("unbound open failed to validate current MUM")
	}
	foreign, err := newPackageMetadataIndex(entries, open, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.OpenCatalogWithManifest(name, snapshot); err == nil {
		t.Fatal("accepted other index snapshot")
	}
	if _, err := index.OpenCatalogWithManifest("other", snapshot); err == nil {
		t.Fatal("accepted other package")
	}
	unbound, err := parseAssemblyFile(&starfile.Bytes{Data: []byte(xml)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := index.OpenCatalogWithManifest(name, unbound); err == nil {
		t.Fatal("accepted equal but unbound bytes")
	}
}
