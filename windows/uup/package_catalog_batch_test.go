package uup

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPackageCatalogBatchOwnership(t *testing.T) {
	const name = "P~31bf3856ad364e35~amd64~~10.0.1.0"
	const text = `<assembly><assemblyIdentity name="P" version="10.0.1.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package/></assembly>`
	catalog := []byte("catalog contents")
	var reads atomic.Int32
	entries := []stageMetadataEntry{{Name: name + ".mum", Path: name + ".mum"}, {Name: name + ".cat", Path: name + ".cat"}}
	open := func(path string) (storage.Reader, error) {
		if strings.HasSuffix(path, ".mum") {
			reads.Add(1)
			return &starfile.Bytes{Data: []byte(text)}, nil
		}
		return &starfile.Bytes{Data: catalog}, nil
	}
	index, err := newPackageMetadataIndex(entries, open, nil)
	if err != nil {
		t.Fatal(err)
	}
	source, err := index.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	manifest := source.(*ParsedAssemblyFile)
	names := []string{name, strings.ToLower(name), name, name}
	files, err := index.OpenCatalogMany(names, []*ParsedAssemblyFile{manifest, manifest, manifest, manifest}, 4)
	if err != nil || len(files) != 4 || reads.Load() != 1 {
		t.Fatalf("batch: %v reads=%d", err, reads.Load())
	}
	copy(catalog, []byte("mutated contents"))
	for i, file := range files {
		data, err := io.ReadAll(io.NewSectionReader(file, 0, file.Size()))
		if err != nil || !bytes.Equal(data, []byte("catalog contents")) {
			t.Fatalf("%d: %q %v", i, data, err)
		}
	}
	foreign, _ := newPackageMetadataIndex(entries, open, nil)
	if files, err := foreign.OpenCatalogMany(names, []*ParsedAssemblyFile{manifest, manifest, manifest, manifest}, 4); err == nil || files != nil {
		t.Fatal("foreign binding accepted")
	}
	for _, workers := range []int{1, 4, 8} {
		files, err := index.OpenCatalogMany([]string{"missing", name}, nil, workers)
		if files != nil || err == nil || !strings.Contains(err.Error(), "input 0:") {
			t.Fatalf("failure atomicity: %v", err)
		}
	}
	if _, err := index.OpenCatalogMany(names, []*ParsedAssemblyFile{manifest}, 4); err == nil {
		t.Fatal("length mismatch")
	}
	if _, err := index.OpenCatalogMany(make([]string, 4097), nil, 4); err == nil {
		t.Fatal("count bound")
	}
	for _, workers := range []int{0, 9} {
		if _, err := index.OpenCatalogMany(names, nil, workers); err == nil {
			t.Fatal("worker bound")
		}
	}
}

func TestPackageCatalogBatchJoinsWorkers(t *testing.T) {
	const suffix = "~31bf3856ad364e35~amd64~~10.0.1.0"
	entered := make(chan struct{}, 4)
	resume := make(chan struct{})
	var active atomic.Int32
	entries := []stageMetadataEntry{}
	names := []string{}
	for i := 0; i < 4; i++ {
		name := fmt.Sprint("P", i) + suffix
		names = append(names, name)
		entries = append(entries, stageMetadataEntry{Name: name + ".mum", Path: name + ".mum"}, stageMetadataEntry{Name: name + ".cat", Path: name + ".cat"})
	}
	index, err := newPackageMetadataIndex(entries, func(path string) (storage.Reader, error) {
		if strings.HasSuffix(path, ".mum") {
			name := strings.Split(path, "~")[0]
			return &starfile.Bytes{Data: []byte(fmt.Sprintf(`<assembly><assemblyIdentity name="%s" version="10.0.1.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package/></assembly>`, name))}, nil
		}
		active.Add(1)
		defer active.Add(-1)
		entered <- struct{}{}
		<-resume
		if strings.HasPrefix(path, "P1~") {
			return nil, fmt.Errorf("expected failure")
		}
		return &starfile.Bytes{Data: []byte("catalog")}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for range 4 {
			<-entered
		}
		close(resume)
	}()
	files, err := index.OpenCatalogMany(names, nil, 4)
	if files != nil || err == nil || !strings.Contains(err.Error(), "input 1:") || active.Load() != 0 {
		t.Fatalf("join: %v active=%d", err, active.Load())
	}
}
