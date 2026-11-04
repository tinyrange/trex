package uup

import (
	"crypto/sha256"
	"io"
	"testing"

	"github.com/tinyrange/trex/archive/wim"
)

func TestUnchangedFileInNewerComponent(t *testing.T) {
	const stem = "amd64_test_token_10.0.26100.9457_none_new"
	const name = "amd64_test_token_10.0.26100.1591_none_old/file.bin"
	data := []byte("unchanged payload")
	a := &testAssemblyArchive{files: map[string][]byte{"/image6/Windows/WinSxS/" + stem + "/file.bin": data}, entries: []wim.EntryInfo{{Name: stem, Directory: true}}}
	r := &reverseAssemblyResolver{base: a, imagePath: "/image6"}
	d := ContentDescriptor{Name: name, Length: int64(len(data)), SHA256: sha256.Sum256(data)}
	f, found, err := r.resolve(d)
	if err != nil || !found {
		t.Fatalf("unchanged basis: %v %v", found, err)
	}
	got, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
	if err != nil || string(got) != string(data) {
		t.Fatalf("payload: %q %v", got, err)
	}
	for _, bad := range []ContentDescriptor{
		{Name: name, Length: d.Length, SHA256: sha256.Sum256([]byte("other"))},
		{Name: name, Length: d.Length + 1, SHA256: d.SHA256},
		{Name: "x86_test_token_10.0.26100.1591_none_old/file.bin", Length: d.Length, SHA256: d.SHA256},
	} {
		if _, found, err := r.resolve(bad); err != nil || found {
			t.Fatalf("incorrect identity: %v %v", found, err)
		}
	}
}
