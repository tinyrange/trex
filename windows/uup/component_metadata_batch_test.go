package uup

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestComponentMetadataBatchConcurrentOrderedAndJoined(t *testing.T) {
	const stem = "amd64_microsoft-windows-kernel32_31bf3856ad364e35_10.0.26100.9444_none_2f8379ba064efb69"
	const identity = "Microsoft-Windows-Kernel32, Culture=neutral, Version=10.0.26100.9444, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS"
	const xml = `<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Microsoft-Windows-Kernel32" language="neutral" version="10.0.26100.9444" publicKeyToken="31bf3856ad364e35" processorArchitecture="amd64" versionScope="nonSxS"/></assembly>`
	entered := make(chan struct{}, 32)
	gate := make(chan struct{})
	var active, released atomic.Int32
	index, err := newComponentMetadataIndex([]stageMetadataEntry{{Name: stem + ".manifest", Path: stem + ".manifest"}}, func(name string) (storage.Reader, error) {
		active.Add(1)
		entered <- struct{}{}
		<-gate
		defer active.Add(-1)
		return &starfile.Bytes{Name: name, Data: []byte(xml)}, nil
	}, func(string) { released.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	ids := make([][]byte, 12)
	for i := range ids {
		ids[i] = []byte(identity)
	}
	type outcome struct {
		files []storage.Reader
		err   error
	}
	done := make(chan outcome, 1)
	go func() { files, err := index.OpenMany(ids, 4); done <- outcome{files, err} }()
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(gate)
			t.Fatal("batch did not execute independent reads concurrently")
		}
	}
	if active.Load() != 4 {
		close(gate)
		t.Fatal("unexpected concurrency", active.Load())
	}
	close(gate)
	result := <-done
	if result.err != nil || len(result.files) != len(ids) || active.Load() != 0 || released.Load() != 12 {
		t.Fatalf("batch result/join: %d %v active=%d released=%d", len(result.files), result.err, active.Load(), released.Load())
	}
	missing := []byte(strings.Replace(identity, "10.0.26100.9444", "10.0.26100.1", 1))
	files, err := index.OpenMany([][]byte{missing, []byte(identity), missing}, 8)
	if err != nil || len(files) != 3 || files[0] != nil || files[1] == nil || files[2] != nil {
		t.Fatalf("lost order or unavailable result: %v %v", files, err)
	}
	// Even a syntactically invalid request must not leak partial files or leave
	// an earlier successful native reader running after return.
	files, err = index.OpenMany([][]byte{[]byte(identity), []byte("invalid"), []byte("also invalid")}, 4)
	if err == nil || !strings.Contains(err.Error(), "identity 1:") || files != nil || active.Load() != 0 {
		t.Fatalf("partial result, nondeterministic error or unfinished reader: %v %v", files, err)
	}
	// A correct filename cannot hide invalid decoded metadata in a batch.
	index.open = func(name string) (storage.Reader, error) {
		return &starfile.Bytes{Name: name, Data: []byte(strings.Replace(xml, "nonSxS", "SxS", 1))}, nil
	}
	if files, err := index.OpenMany([][]byte{[]byte(identity)}, 4); err == nil || files != nil {
		t.Fatal("accepted foreign decoded identity")
	}
	for _, workers := range []int{0, 9} {
		if _, err := index.OpenMany(nil, workers); err == nil {
			t.Fatal("accepted invalid workers")
		}
	}
	if _, err := index.OpenMany(make([][]byte, 65537), 4); err == nil {
		t.Fatal("unbounded request")
	}
	if files, err := index.OpenMany(nil, 4); err != nil || len(files) != 0 {
		t.Fatal("empty request", err)
	}
}
