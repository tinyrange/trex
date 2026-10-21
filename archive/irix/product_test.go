package irix

import (
	"bytes"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func descriptorFixture(format uint16) []byte {
	b := bytes.NewBuffer(append([]byte("pd001V650P00"), 0))
	u16 := func(n uint16) { binary.Write(b, binary.BigEndian, n) }
	u32 := func(n uint32) { binary.Write(b, binary.BigEndian, n) }
	str := func(s string) { u16(uint16(len(s))); b.WriteString(s) }
	marks := func() {
		u16(1)
		str("old*")
		str("sw")
		str("base")
		u32(0xffffffff)
		u32(99)
	}
	u16(1988)
	u16(1)
	u16(1987)
	u16(format)
	str("base")
	str("Base system")
	u16(0x50)
	if format >= 4 {
		u32(100)
		str("alternate")
	}
	if format >= 8 {
		u16(0)
		u16(1)
		str("Pidentity")
	}
	u16(1)
	u16(0x58)
	str("sw")
	str("Software")
	u16(2)
	u16(9)
	u32(100)
	if format < 6 {
		u32(0)
		u32(512)
	}
	if format >= 4 {
		str("image alternate")
	}
	if format >= 8 {
		u16(0)
		u16(0)
	}
	u16(1)
	u16(2)
	str("base")
	str("Base subsystem")
	str("build.source")
	u32(0)
	marks()
	u16(1)
	u16(1)
	str("runtime")
	str("sw")
	str("base")
	u32(10)
	u32(20)
	if format >= 4 {
		str("subsystem alternate")
	}
	if format >= 6 {
		u16(0)
	}
	if format >= 8 {
		u16(0)
		u16(1)
		str("s")
	}
	if format >= 9 {
		marks()
	}
	return b.Bytes()
}
func TestProductGenerationsAndSentinels(t *testing.T) {
	for _, format := range []uint16{3, 5, 6, 8, 9} {
		b := descriptorFixture(format)
		p, err := ReadProducts(&starfile.Bytes{Data: b}, 100)
		if err != nil {
			t.Fatal(format, err)
		}
		im := p[0].Images[0]
		ss := im.Subsystems[0]
		if p[0].Name != "base" || im.Version != 100 || ss.Replacements[0].Low != -1 || len(ss.Prerequisites) != 1 || ss.Prerequisites[0][0].High != 20 {
			t.Fatal("lost descriptor semantics", p)
		}
		padded := append(append([]byte(nil), b...), make([]byte, (512-len(b)%512)%512)...)
		if _, err := ReadProducts(&starfile.Bytes{Data: padded}, 100); err != nil {
			t.Fatal(err)
		}
		padded[len(padded)-1] = 1
		if _, err := ReadProducts(&starfile.Bytes{Data: padded}, 100); err == nil {
			t.Fatal("accepted nonzero fill")
		}
		for _, n := range []int{0, 12, 20, len(b) - 1} {
			if _, err := ReadProducts(&starfile.Bytes{Data: b[:n]}, 100); err == nil {
				t.Fatal("accepted truncated descriptor", n)
			}
		}
		if _, err := ReadProducts(&starfile.Bytes{Data: b}, 1); err == nil {
			t.Fatal("record bound ignored")
		}
	}
}
func TestProductInvalidFields(t *testing.T) {
	b := descriptorFixture(5)
	b[19], b[20] = 0, 255
	if _, err := ReadProducts(&starfile.Bytes{Data: b}, 100); err == nil {
		t.Fatal("accepted unknown version")
	}
	b = descriptorFixture(5)
	b[5] = 'X'
	if _, err := ReadProducts(&starfile.Bytes{Data: b}, 100); err == nil {
		t.Fatal("accepted corrupt wrapper")
	}
}
