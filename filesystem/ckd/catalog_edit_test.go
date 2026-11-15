package ckd

import (
	"bytes"
	"testing"
)

// ciFixture builds a 512-byte KSDS control interval of the records, one
// RDF each.
func ciFixture(records ...[]byte) []byte {
	b := make([]byte, 512)
	pos, rdf := 0, 508
	for _, r := range records {
		pos += copy(b[pos:], r)
		rdf -= 3
		b[rdf+1], b[rdf+2] = byte(len(r)>>8), byte(len(r))
	}
	be.PutUint16(b[508:], uint16(pos))
	be.PutUint16(b[510:], uint16(rdf-pos))
	return b
}

// Removing a record packs the rest, pairs RDFs of equal-length runs as
// VSAM does, and accounts for the freed space in the CIDF.
func TestRemoveCIRecords(t *testing.T) {
	a, b, c, d := bytes.Repeat([]byte{1}, 10), bytes.Repeat([]byte{2}, 10), bytes.Repeat([]byte{3}, 10), bytes.Repeat([]byte{4}, 20)
	out, err := removeCIRecords(ciFixture(a, b, c, d), map[uint64]bool{10: true})
	if err != nil {
		t.Fatal(err)
	}
	ci, err := ParseVSAMInterval(out, VSAMKSDS)
	if err != nil {
		t.Fatal(err)
	}
	if len(ci.Records) != 3 || !bytes.Equal(ci.Records[0], a) || !bytes.Equal(ci.Records[1], c) || !bytes.Equal(ci.Records[2], d) {
		t.Fatalf("records %x", ci.Records)
	}
	// Two equal-length records share a paired RDF: three RDFs in all.
	if ci.FreeOffset != 40 || int(ci.FreeOffset)+int(ci.FreeLength) != 508-9 {
		t.Fatalf("CIDF %d+%d", ci.FreeOffset, ci.FreeLength)
	}
	if _, err := removeCIRecords(ciFixture(a, b), map[uint64]bool{5: true}); err == nil {
		t.Fatal("removed a record inside another")
	}
	out, err = removeCIRecords(ciFixture(a), map[uint64]bool{0: true})
	if err != nil {
		t.Fatal(err)
	}
	if ci, err := ParseVSAMInterval(out, VSAMKSDS); err != nil || len(ci.Records) != 0 || ci.FreeLength != 508 {
		t.Fatalf("emptied CI %+v %v", ci, err)
	}
}
