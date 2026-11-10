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

func TestPlannedRecoveryUsesVerifiedForwardBasis(t *testing.T) {
	// Native PA30 block-swap fixture: recovery must reverse the admitted edge,
	// not use a filename-selected predecessor or a nested record's basis.
	delta, err := hex.DecodeString("504133300000000000000000182320000432000a021d5ddd1550ae83cb1aa8006dbca2e02344d325985685c62c4511a7750b8ef933011db6c307ed19efb47abc7700407c02")
	if err != nil {
		t.Fatal(err)
	}
	var basis []byte
	for i := byte(1); i <= 16; i++ {
		basis = append(basis, bytes.Repeat([]byte{i}, 256)...)
	}
	installed, err := msdelta.ApplyBounded(basis, delta, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	target := ContentDescriptor{Name: "component/file.dll", Length: int64(len(installed)), SHA256: sha256.Sum256(installed)}
	payload := DeltaPayload{DirectDelta: true, Target: target, RecordType: "PA30", Record: ContentDescriptor{Length: int64(len(delta)), SHA256: sha256.Sum256(delta)}, Basis: &ContentDescriptor{Name: "declared-basis", Length: int64(len(basis)), SHA256: sha256.Sum256(basis)}}
	effect := StageFileEffect{Kind: "component-file", SourceMode: "payload", SourceName: target.Name, ExpectedSHA256: &target.SHA256}
	resolutions := 0
	newStage := func(p DeltaPayload, data []byte) *CumulativeStage {
		return &CumulativeStage{PSF: &starfile.Bytes{Data: delta}, expressByTarget: map[string]*DeltaPayload{normalizeCIXName(target.Name): &p}, assemblyResolver: func(d ContentDescriptor) (storage.Reader, error) {
			resolutions++
			if d.Name != "declared-basis" {
				t.Fatalf("unexpected basis %q", d.Name)
			}
			return &starfile.Bytes{Data: data}, nil
		}}
	}
	record, err := newStage(payload, basis).CreatePlannedRecovery(effect, 42)
	if err != nil {
		t.Fatal(err)
	}
	if resolutions != 1 {
		t.Fatalf("resolved the same predecessor %d times", resolutions)
	}
	fast, err := newStage(payload, basis).CreatePlannedRecoveryWithAudit(effect, 42, false)
	if err != nil || !bytes.Equal(fast, record) || resolutions != 2 {
		t.Fatalf("non-audit recovery differs or resolves twice: %v, calls=%d", err, resolutions)
	}
	recovered, err := msdelta.ApplyPSFRecordBounded(installed, record, 1<<20)
	if err != nil || !bytes.Equal(recovered, basis) {
		t.Fatalf("round trip: %v", err)
	}
	literalStage := newStage(payload, basis)
	literalStage.PSF = nil // A literal reverse record must not decode the forward PSF.
	before := resolutions
	size, err := literalStage.PlannedLiteralRecoverySize(effect)
	if err != nil || resolutions != before {
		t.Fatalf("size resolved payload: %v", err)
	}
	literal, err := literalStage.CreatePlannedLiteralRecovery(effect, 42)
	if err != nil || int64(len(literal)) != size || resolutions != before+1 {
		t.Fatalf("literal generation: %v", err)
	}
	recovered, err = msdelta.ApplyPSFRecordBounded(installed, literal, 1<<20)
	if err != nil || !bytes.Equal(recovered, basis) {
		t.Fatalf("literal roundtrip: %v", err)
	}
	broken := bytes.Clone(basis)
	broken[0] ^= 1
	if _, err := newStage(payload, broken).CreatePlannedLiteralRecovery(effect, 42); err == nil {
		t.Fatal("literal accepted corrupt basis")
	}
	for _, test := range []struct {
		name       string
		mutate     func(*StageFileEffect, *DeltaPayload)
		wrongBasis bool
	}{
		{name: "missing planned identity", mutate: func(e *StageFileEffect, p *DeltaPayload) { e.ExpectedSHA256 = nil }},
		{name: "wrong planned identity", mutate: func(e *StageFileEffect, p *DeltaPayload) { e.ExpectedSHA256 = &[32]byte{1} }},
		{name: "wrong file", mutate: func(e *StageFileEffect, p *DeltaPayload) { e.SourceName = "other/file.dll" }},
		{name: "not payload", mutate: func(e *StageFileEffect, p *DeltaPayload) { e.SourceMode = "installed" }},
		{name: "not component", mutate: func(e *StageFileEffect, p *DeltaPayload) { e.Kind = "manifest" }},
		{name: "no basis", mutate: func(e *StageFileEffect, p *DeltaPayload) { p.Basis = nil }},
		{name: "literal", mutate: func(e *StageFileEffect, p *DeltaPayload) { p.Literal = true }},
		{name: "bad record", mutate: func(e *StageFileEffect, p *DeltaPayload) { p.Record.SHA256[0] ^= 1 }},
		{name: "bad target", mutate: func(e *StageFileEffect, p *DeltaPayload) { p.Target.Length++ }},
		{name: "oversize", mutate: func(e *StageFileEffect, p *DeltaPayload) { p.Target.Length = 129 << 20 }},
		{name: "wrong basis bytes", wrongBasis: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			e, p := effect, payload
			if test.mutate != nil {
				test.mutate(&e, &p)
			}
			data := append([]byte(nil), basis...)
			if test.wrongBasis {
				data[0] ^= 1
			}
			for _, audit := range []bool{false, true} {
				if _, err := newStage(p, data).CreatePlannedRecoveryWithAudit(e, 42, audit); err == nil {
					t.Fatalf("accepted unbound recovery (audit=%v)", audit)
				}
			}
		})
	}
}

func TestPlannedRecoveryExactIndexLookup(t *testing.T) {
	name := "amd64_bsdtar_31bf3856ad364e35_10.0.26100.9711_none_f1d074701c1f0699/tar.exe"
	recovery := "amd64_bsdtar_31bf3856ad364e35_10.0.26100.9711_none_f1d074701c1f0699/r/tar.exe"
	effect := StageFileEffect{Kind: "component-file", SourceName: name}
	stage := &CumulativeStage{Index: &ContainerIndex{Files: []CIXFile{{Name: name}}}}
	if got, err := stage.PlannedRecoveryFile(effect); err != nil || got != nil {
		t.Fatalf("absent: %v %v", got, err)
	}
	stage.Index.Files = append(stage.Index.Files, CIXFile{Name: recovery})
	if got, err := stage.PlannedRecoveryFile(effect); err != nil || got == nil || got.Name != recovery {
		t.Fatalf("present: %v %v", got, err)
	}
	stage.Index.Files = append(stage.Index.Files, CIXFile{Name: recovery})
	if _, err := stage.PlannedRecoveryFile(effect); err == nil {
		t.Fatal("accepted duplicate recovery")
	}
}
