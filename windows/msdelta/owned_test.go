package msdelta

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"reflect"
	"testing"
)

// Existing literal, PE/LZX, LZMS literal, BSDiff, checksum and timestamp
// fixtures retain their expected-byte assertions while exercising both APIs.
func testApplyBothOwnershipModes(t *testing.T, source, delta []byte) ([]byte, error) {
	t.Helper()
	original := bytes.Clone(source)
	want, wantErr := Apply(source, delta)
	if !bytes.Equal(source, original) {
		t.Fatal("borrowed source changed")
	}
	got, err := ApplyOwnedBounded(bytes.Clone(source), delta, ^uint64(0))
	if !bytes.Equal(got, want) || fmt.Sprint(err) != fmt.Sprint(wantErr) {
		t.Fatalf("ownership changed result/error: %v / %v", err, wantErr)
	}
	record := make([]byte, 4+len(delta))
	binary.LittleEndian.PutUint32(record, crc32.ChecksumIEEE(delta))
	copy(record[4:], delta)
	wantRecord, wantRecordErr := ApplyPSFRecordBounded(source, record, ^uint64(0))
	gotRecord, gotRecordErr := ApplyPSFRecordOwnedBounded(bytes.Clone(source), record, ^uint64(0))
	if !bytes.Equal(gotRecord, wantRecord) || fmt.Sprint(gotRecordErr) != fmt.Sprint(wantRecordErr) {
		t.Fatalf("PSF ownership changed result/error: %v / %v", gotRecordErr, wantRecordErr)
	}
	for _, bound := range []uint64{0, 1} {
		a, e := ApplyBounded(source, delta, bound)
		b, f := ApplyOwnedBounded(bytes.Clone(source), delta, bound)
		if !bytes.Equal(a, b) || fmt.Sprint(e) != fmt.Sprint(f) {
			t.Fatal("owned target bound differs")
		}
	}
	record[0] ^= 1
	badSource := bytes.Clone(source)
	if _, err := ApplyPSFRecordOwnedBounded(badSource, record, ^uint64(0)); err == nil || !bytes.Equal(badSource, source) {
		t.Fatal("PSF checksum not rejected before source mutation")
	}
	return want, wantErr
}

func ownershipPreprocess() []byte {
	p := newTestBitWriter()
	writeTestRawBits(p, 0x10000000, 64)
	writeTestRawBits(p, 0, 32)
	writeTestRawBits(p, 0x55667788, 32)
	for range 4 {
		p.bit(0)
	}
	return p.bytes()
}

func TestOwnedPENormalizationPreservesRestoreFacts(t *testing.T) {
	managed, _ := makeTestCLIImage(t)
	for _, source := range [][]byte{makeTestPE32(0x10000000, 0x87654321, 0x11223344), managed} {
		before := bytes.Clone(source)
		want, facts, err := preparePE(source, ownershipPreprocess(), 0)
		if err != nil {
			t.Fatal(err)
		}
		owned := bytes.Clone(source)
		got, ownedFacts, err := preparePETracedSource(owned, ownershipPreprocess(), 0, nil, true)
		if err != nil || !bytes.Equal(got, want) || !reflect.DeepEqual(ownedFacts, facts) {
			t.Fatalf("normalization/restore facts differ: %v", err)
		}
		if !bytes.Equal(source, before) {
			t.Fatal("borrowed preprocessing mutated source")
		}
		if &source[0] == &managed[0] {
			if &got[0] == &owned[0] {
				t.Fatal("managed preprocessing lost its original-byte snapshot")
			}
		} else if &got[0] != &owned[0] {
			t.Fatal("native owned buffer was copied")
		}
	}
}

func BenchmarkOwnedPENormalization(b *testing.B) {
	source := make([]byte, 16<<20)
	copy(source, makeTestPE32(0x10000000, 0x87654321, 0x11223344))
	prep := ownershipPreprocess()
	for _, owned := range []bool{false, true} {
		b.Run(fmt.Sprint(owned), func(b *testing.B) {
			data := make([]byte, len(source))
			b.SetBytes(int64(len(source)))
			b.ReportAllocs()
			for b.Loop() {
				copy(data, source)
				if _, _, err := preparePETracedSource(data, prep, 0, nil, owned); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
