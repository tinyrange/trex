package uup

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestExactPackageCatalogCompanions(t *testing.T) {
	const pkg = "P~31bf3856ad364e35~amd64~~10.0.1.0"
	const xml = `<assembly><assemblyIdentity name="P" version="10.0.1.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package/></assembly>`
	for _, mum := range []string{pkg + ".mum", "update.mum"} {
		entries := []stageMetadataEntry{{Name: mum, Path: "/image1/dir/" + mum}, {Name: mum[:len(mum)-4] + ".cat", Path: "/image1/dir/" + mum[:len(mum)-4] + ".CAT"}}
		open := func(p string) (storage.Reader, error) {
			if p == entries[0].Path {
				return &starfile.Bytes{Data: []byte(xml)}, nil
			}
			if p == entries[1].Path {
				return &starfile.Bytes{Data: []byte("catalog")}, nil
			}
			return nil, fmt.Errorf("unexpected lookup %s", p)
		}
		index, err := newPackageMetadataIndex(entries, open, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := index.OpenCatalog(pkg)
		if err != nil || got.Size() != 7 {
			t.Fatalf("companion: %v", err)
		}
		if _, err := index.OpenCatalog("../" + pkg); err == nil {
			t.Fatal("accepted arbitrary path")
		}
		// A same-basename catalog in another directory is NOT a companion.
		entries[1].Path = "/image1/other/" + mum[:len(mum)-4] + ".cat"
		index, err = newPackageMetadataIndex(entries, open, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := index.OpenCatalog(pkg); err == nil {
			t.Fatal("accepted basename fallback")
		}
		entries[1].Path = entries[0].Path[:len(entries[0].Path)-4] + ".cat"
		duplicate := append(append([]stageMetadataEntry{}, entries...), stageMetadataEntry{Name: "duplicate.cat", Path: entries[1].Path[:len(entries[1].Path)-4] + ".CAT"})
		if _, err := newPackageMetadataIndex(duplicate, open, nil); err == nil {
			t.Fatal("accepted ambiguous companion")
		}
	}
}
