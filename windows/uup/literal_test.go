package uup

import (
	"bytes"
	"crypto/sha256"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestMainPSFLiteralComponentTargets(t *testing.T) {
	const stem = `amd64_component_token_10.0.26100.9168_none_hash\`
	data := []byte("MSCF complete cabinet bytes, not a delta")
	hash := sha256.Sum256(data)
	makeFile := func(name string) CIXFile {
		return CIXFile{Name: name, Length: int64(len(data)), Hash: hash, Sources: []CIXSource{{Type: "RAW", Offset: 0, Length: int64(len(data)), Hash: hash}}}
	}
	psf := &ContainerIndex{Type: "PSF", Length: int64(len(data)), Files: []CIXFile{
		makeFile(stem + "firmware.cab"), makeFile("historycix.cab"),
		makeFile(stem + `f\orphan.dll`), makeFile(stem + `r\orphan.dll`),
	}}
	history := &ContainerIndex{Type: "PSFX"}
	graph, err := BuildCumulativeGraph(psf, history)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Payloads) != 1 || !graph.Payloads[0].Literal || graph.Payloads[0].Target.Name != stem+"firmware.cab" {
		t.Fatalf("payloads = %+v", graph.Payloads)
	}
	for _, corrupt := range []bool{false, true} {
		stored := append([]byte(nil), data...)
		if corrupt {
			stored[0] ^= 1
		}
		stage := &CumulativeStage{PSF: &starfile.Bytes{Data: stored}, canonicalCache: make(map[string][]byte)}
		got, err := stage.materializeExpress(graph.Payloads[0])
		if corrupt {
			if err == nil {
				t.Fatal("accepted corrupt literal")
			}
		} else if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("literal = %q: %v", got, err)
		}
	}
	for _, mutate := range []func(*CIXFile){
		func(f *CIXFile) { f.Sources[0].Offset = -1 },
		func(f *CIXFile) { f.Sources[0].Offset = 1 },
		func(f *CIXFile) { f.Sources[0].Length-- },
		func(f *CIXFile) { f.Sources[0].Hash[0] ^= 1 },
		func(f *CIXFile) { f.Sources[0].Name = "unexpected" },
	} {
		psf.Files = []CIXFile{makeFile(stem + "firmware.cab")}
		mutate(&psf.Files[0])
		if _, err := BuildCumulativeGraph(psf, history); err == nil {
			t.Fatal("accepted malformed RAW identity/range")
		}
	}
}
