package ckd

import (
	"encoding/binary"
	"testing"
)

func TestControlIntervalRepeatedRecords(t *testing.T) {
	// Mixed layout from the observed master-catalog RDF convention; payload
	// markers independently verify order, boundaries and repeated record count.
	b := make([]byte, 512)
	copy(b, []byte("abcDEFGHijklm"))
	copy(b[499:], []byte{8, 0, 2, 0x40, 0, 5, 0, 0, 3})
	binary.BigEndian.PutUint16(b[508:], 13)
	binary.BigEndian.PutUint16(b[510:], 486)
	c, e := ParseControlInterval(b)
	if e != nil {
		t.Fatal(e)
	}
	want := []string{"abc", "DEFGH", "ijklm"}
	if len(c.Records) != len(want) {
		t.Fatal(len(c.Records))
	}
	for i, w := range want {
		if string(c.Records[i]) != w {
			t.Fatalf("record %d: %q", i, c.Records[i])
		}
	}
	for _, tc := range []struct {
		name  string
		at    int
		value byte
	}{
		{"unsupported span", 505, 0x10}, {"missing count", 502, 0},
		{"bad count flag", 499, 0}, {"zero count", 501, 0},
		{"overrun", 504, 255}, {"uncovered data", 509, 14},
		{"boundary overlap", 510, 255},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := append([]byte(nil), b...)
			bad[tc.at] = tc.value
			if _, e := ParseControlInterval(bad); e == nil {
				t.Fatal("accepted malformed CI")
			}
		})
	}
}

func TestControlIntervalEmptyAndInvalid(t *testing.T) {
	b := make([]byte, 4096)
	binary.BigEndian.PutUint16(b[4094:], 4092)
	c, e := ParseControlInterval(b)
	if e != nil || len(c.Records) != 0 {
		t.Fatalf("%+v %v", c, e)
	}
	for _, n := range []int{0, 4, 511, 513, 65536} {
		if _, e := ParseControlInterval(make([]byte, n)); e == nil {
			t.Fatalf("accepted size %d", n)
		}
	}
	// Software EOF is distinct from a formatted empty interval. The caller
	// must establish that this is a VSAM data CI, not arbitrary zero allocation.
	eof, e := ParseControlInterval(make([]byte, 4096))
	if e != nil || !eof.EOF || c.EOF {
		t.Fatalf("EOF: %+v %v", eof, e)
	}
}
