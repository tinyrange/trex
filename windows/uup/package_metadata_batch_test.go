package uup

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestPackageMetadataMany(t *testing.T) {
	const suffix = "~31bf3856ad364e35~amd64~~10.0.1.0"
	var active, maximum, releases atomic.Int32
	// Hold the first four opens until all workers enter. This verifies actual
	// parallel reads without a timing-dependent sleep or a leaked worker.
	entered := make(chan struct{}, 4)
	resume := make(chan struct{})
	go func() {
		for range 4 {
			<-entered
		}
		close(resume)
	}()
	index, err := newPackageMetadataIndex([]stageMetadataEntry{
		{Name: "P" + suffix + ".mum", Path: "p"}, {Name: "Bad" + suffix + ".mum", Path: "bad"},
	}, func(path string) (storage.Reader, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		if maximum.Load() < 4 || len(entered) < 4 {
			select {
			case entered <- struct{}{}:
			default:
			}
		}
		<-resume
		name := "P"
		if path == "bad" {
			name = "Other"
		}
		xml := fmt.Sprintf(`<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="%s" version="10.0.1.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package/></assembly>`, name)
		return &starfile.Bytes{Data: []byte(xml)}, nil
	}, func(string) { releases.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"P" + suffix, "p" + suffix, "P" + suffix, "p" + suffix}
	files, err := index.OpenMany(names, 4)
	if err != nil || len(files) != 4 || maximum.Load() != 4 || active.Load() != 0 || releases.Load() != 4 {
		t.Fatalf("batch: %v %v %d %d %d", files, err, maximum.Load(), active.Load(), releases.Load())
	}
	for i, file := range files {
		parsed, ok := file.(*ParsedAssemblyFile)
		if !ok || parsed.Manifest().Identity.Name != "P" {
			t.Fatal("lost parsed snapshot", i)
		}
		for j := 0; j < i; j++ {
			if files[j] == file {
				t.Fatal("duplicate snapshot alias")
			}
		}
	}
	for _, workers := range []int{1, 4, 8} {
		files, err := index.OpenMany([]string{"missing", "Bad" + suffix, "P" + suffix}, workers)
		if files != nil || err == nil || !strings.Contains(err.Error(), "input 0:") || active.Load() != 0 {
			t.Fatalf("error/join: %v %v", files, err)
		}
		files, err = index.OpenMany([]string{"Bad" + suffix}, workers)
		if files != nil || err == nil || !strings.Contains(err.Error(), "identity") {
			t.Fatalf("identity bypass: %v %v", files, err)
		}
	}
	for _, workers := range []int{0, 9} {
		if _, err := index.OpenMany(names, workers); err == nil {
			t.Fatal("workers")
		}
	}
	if _, err := index.OpenMany(make([]string, 4097), 4); err == nil {
		t.Fatal("batch bound")
	}
	if files, err := index.OpenMany(nil, 4); err != nil || len(files) != 0 {
		t.Fatal("empty", err)
	}
}
