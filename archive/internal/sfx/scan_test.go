package sfx

import (
	"bytes"
	"testing"
)

func TestCandidatesCrossChunkAndLimits(t *testing.T) {
	magic := []byte("signature")
	b := make([]byte, 200000)
	copy(b[65533:], magic)
	copy(b[140000:], magic)
	cs, err := Candidates(bytes.NewReader(b), magic, 100000)
	if err != nil || len(cs) != 1 || cs[0].Size() != int64(len(b)-65533) {
		t.Fatalf("%v %v", cs, err)
	}
	got := make([]byte, len(magic))
	if _, err := cs[0].ReadAt(got, 0); err != nil || !bytes.Equal(got, magic) {
		t.Fatalf("%q %v", got, err)
	}
	cs, err = Candidates(bytes.NewReader(bytes.Repeat(magic, 100)), magic, 10000)
	if err != nil || len(cs) != 32 {
		t.Fatalf("candidate bound: %d %v", len(cs), err)
	}
}
