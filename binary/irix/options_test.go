package irix

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestMIPSOptionsAndABIFlags(t *testing.T) {
	for _, class := range []int{32, 64} {
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			b := make([]byte, 64)
			size := 32
			gpOffset := 28
			if class == 64 {
				size, gpOffset = 40, 32
			}
			b[0], b[1] = 1, byte(size)
			if class == 64 {
				order.PutUint64(b[gpOffset:], 0x1234567887654321)
			} else {
				order.PutUint32(b[gpOffset:], 0x87654321)
			}
			p := parser{file: &starfile.Bytes{Data: b}, order: order}
			im := &Image{Class: class}
			if err := p.mipsOptions(im, 0, uint64(size)); err != nil {
				t.Fatal(err)
			}
			if err := p.mipsOptions(im, 0, uint64(size)); err != nil || len(im.Options) != 1 {
				t.Fatal("duplicate option range", err)
			}
			expected := uint64(0x87654321)
			if class == 64 {
				expected = 0x1234567887654321
			}
			if im.GP != expected || len(im.Options) != 1 {
				t.Fatal(im)
			}
			p.seenOptions = nil
			b[1] = 0
			if err := p.mipsOptions(im, 0, uint64(size)); err == nil {
				t.Fatal("zero option length accepted")
			}
			flags := make([]byte, 24)
			flags[2], flags[4], flags[7] = 3, 2, 1
			order.PutUint32(flags[12:], 0x12)
			p.file = &starfile.Bytes{Data: flags}
			if err := p.abiFlags(im, 0, 24); err != nil {
				t.Fatal(err)
			}
			if im.ABIFlags.ISALevel != 3 || im.ABIFlags.ASEs != 0x12 {
				t.Fatal(im)
			}
			order.PutUint16(flags, 1)
			if err := p.abiFlags(im, 0, 24); err == nil {
				t.Fatal("unknown ABI flags generation accepted")
			}
		}
	}
}
