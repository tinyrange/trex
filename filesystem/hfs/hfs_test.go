package hfs

import (
	"bytes"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func tree(records ...[]byte) []byte {
	b := make([]byte, 1024)
	b[8] = 1
	be.PutUint16(b[10:], 3)
	be.PutUint16(b[14:], 1)
	be.PutUint32(b[16:], 1)
	be.PutUint32(b[20:], uint32(len(records)))
	be.PutUint32(b[24:], 1)
	be.PutUint32(b[28:], 1)
	be.PutUint16(b[32:], 512)
	be.PutUint32(b[36:], 2)
	b[512+8] = 255
	b[512+9] = 1
	be.PutUint16(b[512+10:], uint16(len(records)))
	pos := 14
	for i, r := range records {
		be.PutUint16(b[1024-2*(i+1):], uint16(pos))
		copy(b[512+pos:], r)
		pos += len(r)
	}
	be.PutUint16(b[1024-2*(len(records)+1):], uint16(pos))
	return b
}
func catalogRecord(parent uint32, name string, data []byte) []byte {
	keySize := 6 + len(name)
	offset := (keySize + 2) &^ 1
	b := make([]byte, offset+len(data))
	b[0] = byte(keySize)
	be.PutUint32(b[2:], parent)
	b[6] = byte(len(name))
	copy(b[7:], name)
	copy(b[offset:], data)
	return b
}
func fixture() []byte {
	b := make([]byte, 2048+32*512)
	m := b[1024:]
	be.PutUint16(m, 0x4244)
	be.PutUint16(m[18:], 32)
	be.PutUint32(m[20:], 512)
	be.PutUint16(m[28:], 4)
	m[36] = 1
	m[37] = 'V'
	be.PutUint32(m[130:], 1024)
	be.PutUint16(m[134:], 0)
	be.PutUint16(m[136:], 2)
	be.PutUint32(m[146:], 1024)
	be.PutUint16(m[150:], 2)
	be.PutUint16(m[152:], 2)
	overflow := make([]byte, 20)
	overflow[0] = 7
	be.PutUint32(overflow[2:], 16)
	be.PutUint16(overflow[6:], 3)
	be.PutUint16(overflow[8:], 11)
	be.PutUint16(overflow[10:], 1)
	copy(b[2048:], tree(overflow))
	root := make([]byte, 70)
	root[0] = 1
	be.PutUint32(root[6:], 2)
	file := make([]byte, 102)
	file[0] = 2
	be.PutUint32(file[20:], 16)
	be.PutUint32(file[26:], 1537)
	be.PutUint32(file[36:], 3)
	for i, start := range []uint16{5, 7, 9} {
		be.PutUint16(file[74+i*4:], start)
		be.PutUint16(file[76+i*4:], 1)
	}
	be.PutUint16(file[86:], 13)
	be.PutUint16(file[88:], 1)
	copy(b[2048+2*512:], tree(catalogRecord(1, "V", root), catalogRecord(2, "a", file)))
	for i, start := range []int{5, 7, 9, 11} {
		for j := 0; j < 512; j++ {
			b[2048+start*512+j] = byte(i + 1)
		}
	}
	copy(b[2048+13*512:], "res")
	return b
}
func TestBothForksAndOverflow(t *testing.T) {
	v, err := Open(&starfile.Bytes{Data: fixture()}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if string(v.Name) != "V" || len(v.Entries) != 2 || v.Entries[1].Path != "/a" {
		t.Fatalf("%+v", v)
	}
	e := v.Entries[1]
	data, err := starfile.ReadAll(e.Data)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append(append(bytes.Repeat([]byte{1}, 512), bytes.Repeat([]byte{2}, 512)...), bytes.Repeat([]byte{3}, 512)...), 4)
	if !bytes.Equal(data, want) {
		t.Fatal("incorrect fragmented data fork")
	}
	resource, err := starfile.ReadAll(e.Resource)
	if err != nil || string(resource) != "res" {
		t.Fatalf("resource %q %v", resource, err)
	}
}
func TestMalformed(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"geometry":         func(b []byte) { be.PutUint32(b[1044:], 0) },
		"catalog cycle":    func(b []byte) { be.PutUint32(b[2048+3*512:], 1) },
		"catalog count":    func(b []byte) { be.PutUint32(b[2048+2*512+20:], 3) },
		"catalog offset":   func(b []byte) { be.PutUint16(b[2048+4*512-2:], 0) },
		"overflow missing": func(b []byte) { be.PutUint16(b[2048+512+14+6:], 4) },
		"overflow range":   func(b []byte) { be.PutUint16(b[2048+512+14+8:], 32) },
	} {
		t.Run(name, func(t *testing.T) {
			b := fixture()
			mutate(b)
			if _, err := Open(&starfile.Bytes{Data: b}, 100); err == nil {
				t.Fatal("accepted corrupt volume")
			}
		})
	}
	if _, err := Open(&starfile.Bytes{Data: fixture()}, 1); err == nil {
		t.Fatal("ignored entry limit")
	}
}
func TestComponentBytes(t *testing.T) {
	for input, want := range map[string]string{"a/b": "a%2Fb", "a%b": "a%25b", "\x80": "%80", "..": "%2E%2E"} {
		if got := component([]byte(input)); got != want {
			t.Fatalf("%q -> %q", input, got)
		}
	}
}
