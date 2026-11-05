package uup

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"github.com/tinyrange/trex/archive/wim"
	"github.com/tinyrange/trex/compression/lzms"
	"github.com/tinyrange/trex/storage"
	"io"
	"testing"
)

func TestPlannedPredecessorReturnsVerifiedLogicalDCSContent(t *testing.T) {
	// Independent Microsoft Compression API fixture shared with lzms tests.
	raw, err := base64.StdEncoding.DecodeString("OBPQvwAA0HSBfr66/srvvq3e")
	if err != nil {
		t.Fatal(err)
	}
	want, err := lzms.Decompress(raw, 8192)
	if err != nil {
		t.Fatal(err)
	}
	stored := []byte{'D', 'C', 'S', 1, 1, 0, 0, 0, 0, 32, 0, 0}
	stored = binary.LittleEndian.AppendUint32(stored, uint32(len(raw)+4))
	stored = binary.LittleEndian.AppendUint32(stored, 8192)
	stored = append(stored, raw...)
	const stem = "amd64_test_token_10.0.26100.9457_none_new"
	const name = stem + "/file.bin"
	a := &testAssemblyArchive{files: map[string][]byte{"/image6/Windows/WinSxS/" + name: stored}, entries: []wim.EntryInfo{{Name: stem, Directory: true}}}
	descriptor := ContentDescriptor{Name: name, Length: int64(len(want)), SHA256: sha256.Sum256(want)}
	for _, reverse := range []bool{false, true} {
		state := &assemblyContentState{reverse: &reverseAssemblyResolver{base: a, imagePath: "/image6"}}
		resolver := state.snapshotResolver()
		if !reverse {
			resolver = func(d ContentDescriptor) (storage.Reader, error) {
				return resolveBaseAssemblyDescriptor(a, "/image6", d)
			}
		}
		stage := &CumulativeStage{assemblyResolver: resolver}
		effect := StageFileEffect{Kind: "component-file", SourceMode: "predecessor", SourceName: name, SourceDescriptor: &descriptor}
		f, err := stage.OpenPlannedFile(effect)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("logical content: %v", err)
		}
		bad := descriptor
		bad.SHA256[0] ^= 1
		effect.SourceDescriptor = &bad
		if _, err := stage.OpenPlannedFile(effect); err == nil {
			t.Fatal("accepted wrong logical hash")
		}
	}
}
