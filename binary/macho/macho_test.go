package macho

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"io"
	"testing"
)

type source []byte

func (s source) Size() int64                             { return int64(len(s)) }
func (s source) ReadAt(b []byte, off int64) (int, error) { return bytes.NewReader(s).ReadAt(b, off) }
func fixture() source {
	b := make(source, 160)
	u32, u64 := binary.LittleEndian.PutUint32, binary.LittleEndian.PutUint64
	u32(b, 0xfeedfacf)
	u32(b[4:], AMD64)
	u32(b[12:], 11)
	u32(b[16:], 2)
	u32(b[20:], 96)
	c := b[32:]
	u32(c, 0x19)
	u32(c[4:], 72)
	copy(c[8:], "__TEXT")
	u64(c[24:], 0x1000)
	u64(c[32:], 160)
	u64(c[48:], 160)
	u32(c[68:], 8)
	c = b[104:]
	u32(c, 2)
	u32(c[4:], 24)
	u32(c[8:], 128)
	u32(c[12:], 1)
	u32(c[16:], 144)
	u32(c[20:], 16)
	c = b[128:]
	u32(c, 1)
	c[4] = 0xf
	c[5] = 1
	u64(c[8:], 0x1008)
	copy(b[145:], "_probe")
	return b
}
func TestThinSymbolsAndBorrowedVirtualBytes(t *testing.T) {
	b := fixture()
	image, err := Open(b, AMD64)
	if err != nil {
		t.Fatal(err)
	}
	native, err := macho.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(image.Symbols) != 1 || image.Symbols[0].Name != native.Symtab.Syms[0].Name || image.Symbols[0].Address != native.Symtab.Syms[0].Value {
		t.Fatalf("symbols %+v", image.Symbols)
	}
	if image.Segments[0].Flags != native.Segment("__TEXT").Flag {
		t.Fatal("protection flags differ from independent reader")
	}
	r, err := image.At(0x1091, 6)
	if err != nil {
		t.Fatal(err)
	}
	b[145] = 'X'
	got, err := io.ReadAll(io.NewSectionReader(r, 0, r.Size()))
	if err != nil || string(got) != "Xprobe" {
		t.Fatalf("borrowed bytes %q %v", got, err)
	}
	for _, v := range [][2]uint64{{0xfff, 1}, {0x109f, 2}, {^uint64(0), 2}} {
		if _, err := image.At(v[0], v[1]); err == nil {
			t.Fatalf("accepted virtual range %x", v)
		}
	}
}
func TestFatSelectionAndInvalidMetadata(t *testing.T) {
	thin := fixture()
	fat := make(source, 4096+len(thin))
	binary.BigEndian.PutUint32(fat, 0xcafebabe)
	binary.BigEndian.PutUint32(fat[4:], 1)
	a := fat[8:]
	binary.BigEndian.PutUint32(a, AMD64)
	binary.BigEndian.PutUint32(a[8:], 4096)
	binary.BigEndian.PutUint32(a[12:], uint32(len(thin)))
	binary.BigEndian.PutUint32(a[16:], 12)
	copy(fat[4096:], thin)
	if _, err := Open(fat, AMD64); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(fat, 0x0100000c); err == nil {
		t.Fatal("selected missing architecture")
	}
	for name, edit := range map[string]func(source){
		"commands":     func(b source) { binary.LittleEndian.PutUint32(b[20:], maxCommands+1) },
		"symbols":      func(b source) { binary.LittleEndian.PutUint32(b[116:], maxSymbols+1) },
		"string-index": func(b source) { binary.LittleEndian.PutUint32(b[128:], 16) },
		"unterminated": func(b source) {
			for i := 145; i < len(b); i++ {
				b[i] = 'x'
			}
		},
		"extent":   func(b source) { binary.LittleEndian.PutUint64(b[80:], 161) },
		"wrapping": func(b source) { binary.LittleEndian.PutUint64(b[56:], ^uint64(0)) },
	} {
		t.Run(name, func(t *testing.T) {
			b := fixture()
			edit(b)
			if _, err := Open(b, AMD64); err == nil {
				t.Fatal("accepted malformed image")
			}
		})
	}
	binary.BigEndian.PutUint32(fat[20:], uint32(len(fat)))
	if _, err := Open(fat, AMD64); err == nil {
		t.Fatal("accepted fat extent past EOF")
	}
}
