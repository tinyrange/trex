package uup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/msdelta"
)

func TestMainPSFDirectDeltaTarget(t *testing.T) {
	// Same portable CreateDelta block-swap fixture used by msdelta's decoder
	// tests. It is a PA30 stream, not a checksummed PSF record containing one.
	delta, err := hex.DecodeString("504133300000000000000000182320000432000a021d5ddd1550ae83cb1aa8006dbca2e02344d325985685c62c4511a7750b8ef933011db6c307ed19efb47abc7700407c02")
	if err != nil {
		t.Fatal(err)
	}
	header, err := msdelta.Parse(delta)
	if err != nil {
		t.Fatal(err)
	}
	var targetHash [32]byte
	copy(targetHash[:], header.TargetHash)
	const stem = "amd64_component_token_10.0.26100.9711_none_hash/nohistory.dll"
	makeFile := func(name string) CIXFile {
		return CIXFile{Name: name, Length: int64(header.TargetSize), Hash: targetHash, Sources: []CIXSource{{Type: "PA30", Offset: 0, Length: int64(len(delta)), Hash: sha256.Sum256(delta)}}}
	}
	psf := &ContainerIndex{Type: "PSF", Length: int64(len(delta)), Files: []CIXFile{makeFile(stem), makeFile("amd64_component_token_10.0.26100.9711_none_hash/f/record"), makeFile("historycix.cab")}}
	history := &ContainerIndex{Type: "PSFX"}
	reader := &starfile.Bytes{Data: delta}
	graph, err := BuildCumulativeGraphWithRecords(psf, history, reader, 1<<20)
	if err != nil || len(graph.Payloads) != 1 || !graph.Payloads[0].DirectDelta || graph.Payloads[0].RecordTarget != nil {
		t.Fatalf("direct graph: %+v %v", graph, err)
	}
	source := []byte{}
	for value := byte(1); value <= 16; value++ {
		source = append(source, bytes.Repeat([]byte{value}, 256)...)
	}
	want := append([]byte(nil), source...)
	copy(want[256:512], source[512:768])
	copy(want[512:768], source[256:512])
	// This fixture uses a source; supply it explicitly to isolate direct-stream
	// execution from source catalog discovery (its PA30 header has no hash).
	item := graph.Payloads[0]
	item.Basis = &ContentDescriptor{Name: "basis", Length: int64(len(source)), SHA256: sha256.Sum256(source)}
	stage := &CumulativeStage{PSF: reader, assemblyResolver: func(d ContentDescriptor) (storage.Reader, error) { return &starfile.Bytes{Data: source}, nil }}
	got, err := stage.materializeExpress(item)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("direct reconstruction: %v", err)
	}
	for _, mutate := range []func(*CIXFile){
		func(f *CIXFile) { f.Hash[0] ^= 1 },
		func(f *CIXFile) { f.Length++ },
		func(f *CIXFile) { f.Sources[0].Hash[0] ^= 1 },
		func(f *CIXFile) { f.Sources[0].Offset = 1 },
	} {
		psf.Files = []CIXFile{makeFile(stem)}
		mutate(&psf.Files[0])
		if _, err := BuildCumulativeGraphWithRecords(psf, history, reader, 1<<20); err == nil {
			t.Fatal("accepted bad direct identity/range")
		}
	}
}
