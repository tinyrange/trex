package cpio

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"strings"
	"testing"
)

type countForward struct {
	*forwardOnly
	calls int
}

func (r *countForward) ReadAt(p []byte, off int64) (int, error) {
	r.calls++
	return r.forwardOnly.ReadAt(p, off)
}
func largeArchive(count int) []byte {
	var b []byte
	for i := 0; i < count; i++ {
		b = append(b, record("070701", fmt.Sprintf("deep/path/file-%06d", i), "", uint32(i+1), 0100644, 1)...)
	}
	b = append(b, trailer("070701")...)
	return append(b, make([]byte, 512<<10)...)
}
func TestFlatIndexBuffersMetadataAndPadding(t *testing.T) {
	raw := largeArchive(20000)
	r := &countForward{forwardOnly: &forwardOnly{Bytes: &starfile.Bytes{Data: raw}}}
	entries, err := Read(r, 20000)
	if err != nil || len(entries) != 20000 {
		t.Fatal(len(entries), err)
	}
	if entries[0].Name != "deep/path/file-000000" || entries[0].View != nil {
		t.Fatal("fabricated directory tree")
	}
	// Old indexing issued four reads per record and one per padding byte.
	// The new index should issue approximately one read per 64 KiB, not per entry.
	if r.calls > len(raw)/metadataBuffer+100 {
		t.Fatalf("metadata read amplification: %d calls for %d bytes", r.calls, len(raw))
	}
	if _, err := Read(&starfile.Bytes{Data: raw}, 19999); !errors.Is(err, auto.ErrLimit) || !strings.Contains(err.Error(), "file-019999") {
		t.Fatal("missing contextual limit", err)
	}
}
func TestWindowBoundaryNamesLinksAndHardlinkNamespaces(t *testing.T) {
	for _, sig := range []string{"070707", "070701", "070702"} {
		name := strings.Repeat("n", 65535)
		raw := record(sig, name, "", 1, 0100644, 1)
		raw = append(raw, record(sig, "sym", strings.Repeat("x", 65536), 2, 0120777, 1)...)
		raw = append(raw, record(sig, "a", "", 42, 0100644, 2)...)
		raw = append(raw, record(sig, "b", "first", 42, 0100644, 2)...)
		raw = append(raw, trailer(sig)...)
		raw = append(raw, make([]byte, metadataBuffer-4)...)
		raw = append(raw, record(sig, "a", "second", 42, 0100644, 2)...)
		raw = append(raw, record(sig, "c", "", 42, 0100644, 2)...)
		raw = append(raw, trailer(sig)...)
		r := &forwardOnly{Bytes: &starfile.Bytes{Data: raw}}
		entries, err := Read(r, 10)
		if err != nil || len(entries) != 5 {
			t.Fatal(sig, len(entries), err)
		}
		byName := map[string]auto.Entry{}
		for _, e := range entries {
			byName[e.Name] = e
		}
		if byName["sym"].Attributes["target"] != strings.Repeat("x", 65536) {
			t.Fatal("symlink crossing window")
		}
		if byName["b"].Attributes["archive"] == byName["c"].Attributes["archive"] {
			t.Fatal("hardlinks lost archive namespace")
		}
		entries, err = Read(&starfile.Bytes{Data: raw}, 10)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			byName[e.Name] = e
		}
		for path, want := range map[string]string{"a": "second", "b": "first", "c": "second"} {
			got, err := io.ReadAll(io.NewSectionReader(byName[path].Reader, 0, byName[path].Reader.Size()))
			if err != nil || string(got) != want {
				t.Fatal(path, err)
			}
		}
	}
}
func TestBufferedIndexRejectsCorruptSymlinkAndNumbers(t *testing.T) {
	raw := append(record("070702", "link", "target", 1, 0120777, 1), trailer("070702")...)
	raw[bytes.Index(raw, []byte("target"))] ^= 1
	if _, err := Read(&starfile.Bytes{Data: raw}, 5); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatal(err)
	}
	for _, sig := range []string{"070701", "070707"} {
		raw := append(record(sig, "f", "", 1, 0100644, 1), trailer(sig)...)
		raw[6] = '+'
		if _, err := Read(&starfile.Bytes{Data: raw}, 5); err == nil {
			t.Fatal("accepted numeric sign")
		}
	}
}
func BenchmarkIndexLarge(b *testing.B) {
	raw := largeArchive(230000)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Read(&starfile.Bytes{Data: raw}, 230000); err != nil {
			b.Fatal(err)
		}
	}
}
