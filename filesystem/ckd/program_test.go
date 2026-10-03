package ckd

import (
	"bytes"
	"io"
	"testing"
)

func sparseProgram() []byte {
	b := make([]byte, 3*4096)
	copy(b, eb("IEWPLMH", 8))
	be.PutUint32(b[8:], 36)
	b[12] = 3
	be.PutUint32(b[16:], 5*4096)
	be.PutUint32(b[20:], 1)
	be.PutUint16(b[24:], 6)
	be.PutUint32(b[28:], 128)
	be.PutUint32(b[32:], 128)
	copy(b[128:], eb("IEWLIDX", 8))
	be.PutUint32(b[136:], 20)
	b[140] = 1
	be.PutUint32(b[144:], 1)
	b[148] = 3
	be.PutUint32(b[152:], 192)
	be.PutUint32(b[156:], 44)
	copy(b[192:], eb("IEWPGSTB", 8))
	be.PutUint32(b[200:], 44)
	b[204] = 1
	be.PutUint32(b[208:], 2)
	be.PutUint32(b[212:], 4096)
	be.PutUint32(b[216:], 8191)
	be.PutUint32(b[224:], 12288)
	be.PutUint32(b[228:], 16383)
	be.PutUint32(b[232:], 4096)
	for i := 4096; i < len(b); i++ {
		b[i] = byte(i/4096 + 0x40)
	}
	return b
}
func TestProgramSparseRead(t *testing.T) {
	b := sparseProgram()
	p, err := OpenProgramObject(raw(b))
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 5*4096)
	copy(want, b[:4096])
	copy(want[8192:], b[4096:8192])
	copy(want[16384:], b[8192:])
	for _, tt := range []struct{ off, n int }{{0, len(want)}, {4090, 24}, {8190, 4100}, {12000, 5000}, {16380, 4100}, {20480, 1}} {
		got := bytes.Repeat([]byte{255}, tt.n)
		n, err := p.ReadAt(got, int64(tt.off))
		expected := min(tt.n, len(want)-tt.off)
		if n != expected || !bytes.Equal(got[:n], want[tt.off:tt.off+n]) {
			t.Fatalf("read %v: n=%d", tt, n)
		}
		if expected < tt.n && err != io.EOF || expected == tt.n && err != nil {
			t.Fatal(err)
		}
	}
}
func TestProgramRejectsInvalidGaps(t *testing.T) {
	for _, tt := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"overlap", 224, 4096}, {"cumulative", 232, 0}, {"unaligned", 212, 4097},
		{"out of bounds", 228, 0xffffffff}, {"reconciliation", 16, 24576},
		{"count", 208, 3}, {"metadata collision", 212, 0}, {"missing index", 24, 0},
		{"oversize table", 156, 0xffffffff}, {"bad table length", 200, 43},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := sparseProgram()
			be.PutUint32(b[tt.offset:], tt.value)
			if _, err := OpenProgramObject(raw(b)); err == nil {
				t.Fatal("invalid program accepted")
			}
		})
	}
}
