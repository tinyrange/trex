package ckd

import (
	"bytes"
	"testing"
)

func vsamSegmentFixture(kind byte, update uint16, data []byte) []byte {
	b := make([]byte, 512)
	copy(b, data)
	b[502] = ((kind & 0x30) | 8)
	be.PutUint16(b[503:], update)
	b[505] = kind
	be.PutUint16(b[506:], uint16(len(data)))
	be.PutUint16(b[508:], uint16(len(data)))
	be.PutUint16(b[510:], uint16(502-len(data)))
	return b
}
func vsamRecordFixture(data []byte) []byte {
	b := make([]byte, 512)
	copy(b, data)
	be.PutUint16(b[506:], uint16(len(data)))
	be.PutUint16(b[508:], uint16(len(data)))
	be.PutUint16(b[510:], uint16(505-len(data)))
	return b
}
func vsamTestOptions(org VSAMOrganization, n int) VSAMReadOptions {
	return VSAMReadOptions{Organization: org, CIBytes: 512, UsedBytes: uint64(n * 512), CIsPerCA: 10, MaxRecords: 100, MaxRecordBytes: 4096, MaxIntervals: 100, MaxBytes: 10000}
}

func TestVSAMSpannedSnapshot(t *testing.T) {
	first := bytes.Repeat([]byte{'A'}, 502)
	middle := bytes.Repeat([]byte{'B'}, 502)
	b := append(vsamSegmentFixture(0x50, 7, first), vsamSegmentFixture(0x70, 7, middle)...)
	b = append(b, vsamSegmentFixture(0x60, 7, []byte("END"))...)
	b = append(b, vsamRecordFixture([]byte("next"))...)
	o := vsamTestOptions(VSAMESDS, 4)
	rs, e := ReadVSAMRecords(raw(b), o)
	want := append(append(bytes.Clone(first), middle...), []byte("END")...)
	if e != nil || len(rs) != 2 || !bytes.Equal(rs[0].Data, want) || rs[1].RBA != 1536 || rs[1].Number != 2 {
		t.Fatalf("%+v %v", rs, e)
	}
	clear(b)
	if !bytes.Equal(rs[0].Data, want) {
		t.Fatal("results alias source")
	}
	for _, tc := range []struct {
		name   string
		change func([]byte, *VSAMReadOptions)
	}{
		{"generation", func(b []byte, o *VSAMReadOptions) { b[512+504] = 8 }},
		{"wrong pair", func(b []byte, o *VSAMReadOptions) { b[502] = 0x28 }},
		{"orphan", func(b []byte, o *VSAMReadOptions) { b[505] = 0x70; b[502] = 0x38 }},
		{"cross CA", func(b []byte, o *VSAMReadOptions) { o.CIsPerCA = 2 }},
		{"size limit", func(b []byte, o *VSAMReadOptions) { o.MaxRecordBytes = 600 }},
		{"truncated", func(b []byte, o *VSAMReadOptions) { o.UsedBytes = 1024 }},
		{"EOF", func(b []byte, o *VSAMReadOptions) { clear(b[512:1024]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bb := append(vsamSegmentFixture(0x50, 7, first), vsamSegmentFixture(0x70, 7, middle)...)
			bb = append(bb, vsamSegmentFixture(0x60, 7, []byte("END"))...)
			oo := vsamTestOptions(VSAMESDS, 3)
			tc.change(bb, &oo)
			if _, e := ReadVSAMRecords(raw(bb), oo); e == nil {
				t.Fatal("accepted invalid span")
			}
		})
	}
}
func TestVSAMRelativeRecordNumbers(t *testing.T) {
	b := make([]byte, 512)
	copy(b, []byte("aaXXcc"))
	copy(b[499:], []byte{0, 0, 2, 4, 0, 2, 0, 0, 2})
	be.PutUint16(b[508:], 6)
	be.PutUint16(b[510:], 493)
	source := append(bytes.Clone(b), b...)
	rs, e := ReadVSAMRecords(raw(source), vsamTestOptions(VSAMRRDS, 2))
	if e != nil || len(rs) != 4 {
		t.Fatal(rs, e)
	}
	for i, n := range []uint64{1, 3, 4, 6} {
		if rs[i].Number != n || string(rs[i].Data) == "XX" {
			t.Fatal(rs)
		}
	}
	source[504] = 3
	if _, e := ReadVSAMRecords(raw(source), vsamTestOptions(VSAMRRDS, 2)); e == nil {
		t.Fatal("varying RRDS slot accepted")
	}
}
func TestVSAMIndexedOrderAndBounds(t *testing.T) {
	b := append(vsamRecordFixture([]byte("B-body")), vsamRecordFixture([]byte("A-body"))...)
	o := vsamTestOptions(VSAMKSDS, 2)
	o.Order = []uint64{1, 0}
	o.KeyLength = 1
	rs, e := ReadVSAMRecords(raw(b), o)
	if e != nil || len(rs) != 2 || rs[0].RBA != 512 {
		t.Fatal(rs, e)
	}
	for _, order := range [][]uint64{nil, {0, 1}, {1, 1}, {1, 2}} {
		o.Order = order
		if _, e := ReadVSAMRecords(raw(b), o); e == nil {
			t.Fatal("bad index order accepted", order)
		}
	}
	o.Order = []uint64{1, 0}
	o.MaxBytes = 11
	if _, e := ReadVSAMRecords(raw(b), o); e == nil {
		t.Fatal("byte budget ignored")
	}
	o.MaxBytes = 100
	o.MaxIntervals = 1
	if _, e := ReadVSAMRecords(raw(b), o); e == nil {
		t.Fatal("CI budget ignored")
	}
}
