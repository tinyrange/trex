package macho

import (
	"encoding/binary"
	"strings"
	"testing"
)

func manyNames(count int, distinct bool) source {
	const stringSize = 256 << 10
	off := 56 + count*16
	b := make(source, off+stringSize)
	p := binary.LittleEndian.PutUint32
	p(b, 0xfeedfacf)
	p(b[4:], AMD64)
	p(b[16:], 1)
	p(b[20:], 24)
	p(b[32:], 2)
	p(b[36:], 24)
	p(b[40:], 56)
	p(b[44:], uint32(count))
	p(b[48:], uint32(off))
	p(b[52:], stringSize)
	for i := 0; i < count; i++ {
		if distinct {
			p(b[56+i*16:], uint32(i))
		}
	}
	for i := off; i < len(b)-1; i++ {
		b[i] = 'a'
	}
	return b
}
func TestSymbolNamesBoundAmplification(t *testing.T) {
	if _, err := Open(manyNames(300, true), AMD64); err == nil || !strings.Contains(err.Error(), "aggregate") {
		t.Fatalf("overlapping name allocation not bounded: %v", err)
	}
	image, err := Open(manyNames(4096, false), AMD64)
	if err != nil || len(image.Symbols) != 4096 || len(image.Symbols[4095].Name) != (256<<10)-1 {
		t.Fatalf("duplicate string indices must be shared: %v", err)
	}
}
