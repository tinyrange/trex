package uup

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/tinyrange/trex/archive/wim"
	"github.com/tinyrange/trex/windows/msdelta"
)

func TestInheritedRecoveryBindsBaseContent(t *testing.T) {
	const stem = "amd64_test_token_10.0.26100.9457_none_new"
	const other = "amd64_test_token_10.0.26100.9278_none_older"
	const root = "/image6/Windows/WinSxS/" + stem + "/"
	installed := []byte("installed unchanged content")
	checkpoint := []byte("earlier checkpoint")
	record, err := msdelta.CreateReversePSFRecord(installed, checkpoint, 123, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	d := ContentDescriptor{Name: "amd64_test_token_10.0.26100.1150_none_old/file.bin", Length: int64(len(installed)), SHA256: sha256.Sum256(installed)}
	effect := StageFileEffect{Kind: "component-file", SourceMode: "predecessor", SourceDescriptor: &d, ExpectedSHA256: &d.SHA256}
	for _, test := range []struct {
		name                  string
		mutate                func(*testAssemblyArchive, *StageFileEffect)
		wantError, wantAbsent bool
	}{
		{name: "exact"},
		{name: "absent", mutate: func(a *testAssemblyArchive, e *StageFileEffect) { delete(a.files, root+"r/file.bin") }, wantAbsent: true},
		{name: "wrong installed bytes", mutate: func(a *testAssemblyArchive, e *StageFileEffect) {
			a.files[root+"file.bin"] = bytes.Repeat([]byte("x"), len(installed))
		}, wantAbsent: true},
		{name: "plan mismatch", mutate: func(a *testAssemblyArchive, e *StageFileEffect) { e.ExpectedSHA256 = &[32]byte{} }, wantError: true},
		{name: "corrupt record", mutate: func(a *testAssemblyArchive, e *StageFileEffect) { a.files[root+"r/file.bin"][0] ^= 1 }, wantError: true},
		{name: "wrong record source", mutate: func(a *testAssemblyArchive, e *StageFileEffect) {
			a.files[root+"r/file.bin"], _ = msdelta.CreateReversePSFRecord([]byte("wrong"), checkpoint, 123, 1<<20)
		}, wantError: true},
		{name: "ambiguous target", mutate: func(a *testAssemblyArchive, e *StageFileEffect) {
			a.entries = append(a.entries, wim.EntryInfo{Name: other, Directory: true})
			otherRoot := "/image6/Windows/WinSxS/" + other + "/"
			a.files[otherRoot+"file.bin"] = installed
			a.files[otherRoot+"r/file.bin"], _ = msdelta.CreateReversePSFRecord(installed, []byte("different checkpoint"), 123, 1<<20)
		}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := &testAssemblyArchive{files: map[string][]byte{root + "file.bin": installed, root + "r/file.bin": bytes.Clone(record)}, entries: []wim.EntryInfo{{Name: stem, Directory: true}}}
			e := effect
			if test.mutate != nil {
				test.mutate(a, &e)
			}
			s := &CumulativeStage{baseRecovery: &reverseAssemblyResolver{base: a, imagePath: "/image6"}}
			got, err := s.InheritedPlannedRecovery(e)
			if test.wantError {
				if err == nil {
					t.Fatal("accepted invalid recovery")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.wantAbsent {
				if got != nil {
					t.Fatal("returned unrelated recovery")
				}
				return
			}
			if !bytes.Equal(got.Data, record) || got.SourcePath != strings.TrimPrefix(root+"r/file.bin", "/image6") {
				t.Fatal("did not preserve exact record bytes")
			}
		})
	}
}
