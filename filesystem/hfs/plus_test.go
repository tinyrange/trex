package hfs

import (
	"bytes"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
	"unicode/utf16"
)

func plusRecord(parent uint32, name string, data []byte) []byte {
	u := utf16.Encode([]rune(name))
	b := make([]byte, 8+len(u)*2+len(data))
	be.PutUint16(b, uint16(6+len(u)*2))
	be.PutUint32(b[2:], parent)
	be.PutUint16(b[6:], uint16(len(u)))
	for i, c := range u {
		be.PutUint16(b[8+2*i:], c)
	}
	copy(b[8+2*len(u):], data)
	return b
}
func plusFixture() []byte {
	b := make([]byte, 64*512)
	h := b[1024:]
	be.PutUint16(h, 0x482b)
	be.PutUint16(h[2:], 4)
	be.PutUint32(h[40:], 512)
	be.PutUint32(h[44:], 64)
	fork := func(d []byte, size uint64, start, count uint32) {
		be.PutUint64(d, size)
		be.PutUint32(d[12:], count)
		be.PutUint32(d[16:], start)
		be.PutUint32(d[20:], count)
	}
	fork(h[192:], 1024, 6, 2)
	fork(h[272:], 1024, 4, 2)
	ov := make([]byte, 76)
	be.PutUint16(ov, 10)
	be.PutUint32(ov[4:], 16)
	be.PutUint32(ov[8:], 8)
	be.PutUint32(ov[12:], 30)
	be.PutUint32(ov[16:], 1)
	copy(b[6*512:], tree(ov))
	root := make([]byte, 88)
	be.PutUint16(root, 1)
	be.PutUint32(root[8:], 2)
	f := make([]byte, 248)
	be.PutUint16(f, 2)
	be.PutUint32(f[8:], 16)
	be.PutUint64(f[88:], 4097)
	be.PutUint32(f[100:], 9)
	for i := 0; i < 8; i++ {
		start := 10 + i*2
		be.PutUint32(f[104+i*8:], uint32(start))
		be.PutUint32(f[108+i*8:], 1)
		copy(b[start*512:], bytes.Repeat([]byte{byte(i + 1)}, 512))
	}
	b[30*512] = 9
	fork(f[168:], 3, 32, 1)
	copy(b[32*512:], "res")
	copy(b[4*512:], tree(plusRecord(1, "Volume", root), plusRecord(2, "é/😀", f)))
	return b
}
func TestPlusForksUnicodeAndEmbedded(t *testing.T) {
	for _, embedded := range []bool{false, true} {
		b := plusFixture()
		if embedded {
			w := make([]byte, len(b)+2048)
			copy(w[2048:], b)
			be.PutUint16(w[1024:], 0x4244)
			be.PutUint32(w[1044:], 512)
			be.PutUint16(w[1052:], 4)
			be.PutUint16(w[1148:], 0x482b)
			be.PutUint16(w[1152:], 64)
			b = w
		}
		v, err := Open(&starfile.Bytes{Data: b}, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(v.Entries) != 2 || v.Entries[1].Path != "/é%2F😀" {
			t.Fatalf("%+v", v)
		}
		got, err := starfile.ReadAll(v.Entries[1].Data)
		if err != nil || len(got) != 4097 || got[4096] != 9 {
			t.Fatalf("fork %d %v", len(got), err)
		}
		for i := 0; i < 8; i++ {
			if !bytes.Equal(got[i*512:(i+1)*512], bytes.Repeat([]byte{byte(i + 1)}, 512)) {
				t.Fatal("fragmented extent mismatch")
			}
		}
		root := auto.Open(&starfile.Bytes{Data: b}, "disk", auto.Options{})
		n, err := root.Resolve("é%2F😀/resource")
		if err != nil {
			t.Fatal(err)
		}
		got, err = starfile.ReadAll(n.Reader())
		if err != nil || string(got) != "res" {
			t.Fatalf("resource %q %v", got, err)
		}
	}
}
func TestPlusMalformed(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"block":    func(b []byte) { be.PutUint32(b[1064:], 513) },
		"volume":   func(b []byte) { be.PutUint32(b[1068:], 65) },
		"overflow": func(b []byte) { be.PutUint32(b[7*512+14+8:], 9) },
		"cycle":    func(b []byte) { be.PutUint32(b[5*512:], 1) },
		"key":      func(b []byte) { be.PutUint16(b[5*512+14:], 65535) },
	} {
		t.Run(name, func(t *testing.T) {
			b := plusFixture()
			mutate(b)
			if _, err := Open(&starfile.Bytes{Data: b}, 100); err == nil {
				t.Fatal("accepted malformed volume")
			}
		})
	}
	if _, err := unicodeName([]byte{0xd8, 0x00}); err == nil {
		t.Fatal("accepted unpaired surrogate")
	}
	if plusComponent([]byte("\x00\x00HFS+ Private Data")) != "%00%00HFS+ Private Data" {
		t.Fatal("private name encoding")
	}
}
