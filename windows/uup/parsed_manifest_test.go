package uup

import (
	"bytes"
	"io"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestParsedAssemblySnapshot(t *testing.T) {
	raw := []byte(`<assembly><assemblyIdentity name="Original" version="1"/></assembly>`)
	parsed, err := parseAssemblyFile(&starfile.Bytes{Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	// Source mutation must not make validated bytes disagree with the parse.
	copy(raw, bytes.Repeat([]byte("x"), len(raw)))
	got := make([]byte, parsed.Size())
	if _, err := parsed.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `name="Original"`) || parsed.Manifest().Identity.Name != "Original" {
		t.Fatal("source mutation changed the owned snapshot")
	}
	got[0] = 'x'
	if n, err := parsed.ReadAt(got[:1], 0); n != 1 || err != nil || got[0] != '<' {
		t.Fatal("read exposed internal bytes")
	}
}

type invalidManifestReader struct{ size int64 }

func (r invalidManifestReader) Size() int64                     { return r.size }
func (invalidManifestReader) ReadAt([]byte, int64) (int, error) { return 0, io.EOF }

func TestParsedAssemblyRejectsInvalidSource(t *testing.T) {
	for _, size := range []int64{-1, maximumAssemblyManifestSize + 1, 20} {
		if parsed, err := parseAssemblyFile(invalidManifestReader{size}); err == nil || parsed != nil {
			t.Fatalf("accepted invalid size/read %d", size)
		}
	}
	if parsed, err := parseAssemblyFile(&starfile.Bytes{Data: []byte("<assembly>")}); err == nil || parsed != nil {
		t.Fatal("accepted malformed XML")
	}
}
