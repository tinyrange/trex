package hfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func packedData(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zlib.NewWriter(&b)
	if _, err := z.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func compressionAttr(kind uint32, size uint64, data []byte) *starfile.Bytes {
	b := make([]byte, 16)
	copy(b, "fpmc")
	binary.LittleEndian.PutUint32(b[4:], kind)
	binary.LittleEndian.PutUint64(b[8:], size)
	return &starfile.Bytes{Data: append(b, data...)}
}
func cmpfResource(payload []byte) *starfile.Bytes {
	mapOffset := 260 + len(payload)
	b := make([]byte, mapOffset+50)
	be.PutUint32(b, 256)
	be.PutUint32(b[4:], uint32(mapOffset))
	be.PutUint32(b[8:], uint32(4+len(payload)))
	be.PutUint32(b[12:], 50)
	be.PutUint32(b[256:], uint32(len(payload)))
	copy(b[260:], payload)
	m := b[mapOffset:]
	be.PutUint16(m[24:], 28)
	be.PutUint16(m[26:], 50)
	copy(m[30:], "cmpf")
	be.PutUint16(m[36:], 10)
	be.PutUint16(m[40:], 65535)
	return &starfile.Bytes{Data: b}
}
func TestDecmpfsInlineChecksumsStoredAndRaw(t *testing.T) {
	plain := []byte("decoded inode")
	for _, payload := range [][]byte{packedData(t, plain), append([]byte{255}, plain...)} {
		attr := compressionAttr(3, uint64(len(plain)), payload)
		data, kind, err := compressedData(attr, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := starfile.ReadAll(data)
		if err != nil || !bytes.Equal(got, plain) || kind != 3 {
			t.Fatalf("%q %v", got, err)
		}
	}
	payload := packedData(t, plain)
	payload[len(payload)-1] ^= 1
	data, _, err := compressedData(compressionAttr(3, uint64(len(plain)), payload), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := starfile.ReadAll(data); err == nil {
		t.Fatal("corrupt zlib accepted")
	}
	raw := &starfile.Bytes{}
	v := &Volume{Entries: []Entry{{Kind: "file", OwnerFlags: 0x20, Data: raw, Xattrs: map[string]starfile.File{"com.apple.decmpfs": compressionAttr(99, 2, nil)}}}}
	if err := decodeCompressed(v, true); err != nil || v.Entries[0].Data != raw {
		t.Fatal("explicit raw access failed")
	}
	if err := decodeCompressed(v, false); err == nil {
		t.Fatal("unsupported compression silently empty")
	}
}
func TestDecmpfsResourceCrossBlockAndBounds(t *testing.T) {
	first := bytes.Repeat([]byte{'A'}, 65536)
	second := []byte("end")
	a := packedData(t, first)
	b := append([]byte{255}, second...)
	table := make([]byte, 20)
	le := binary.LittleEndian
	le.PutUint32(table, 2)
	le.PutUint32(table[4:], 20)
	le.PutUint32(table[8:], uint32(len(a)))
	le.PutUint32(table[12:], uint32(20+len(a)))
	le.PutUint32(table[16:], uint32(len(b)))
	resource := cmpfResource(append(append(table, a...), b...))
	attr := compressionAttr(4, 65539, nil)
	data, _, err := compressedData(attr, resource)
	if err != nil {
		t.Fatal(err)
	}
	var p [5]byte
	if _, err := data.ReadAt(p[:], 65534); err != nil || string(p[:]) != "AAend" {
		t.Fatalf("crossblock %q %v", p, err)
	}
	if _, err := data.ReadAt(p[:], 0); err != nil || string(p[:]) != "AAAAA" {
		t.Fatalf("backward %q %v", p, err)
	}
	le.PutUint32(resource.Data[264:], 19)
	if _, _, err := compressedData(attr, resource); err == nil {
		t.Fatal("overlapping chunk table accepted")
	}
	if _, _, err := compressedData(compressionAttr(3, 65537, []byte{255}), nil); err == nil {
		t.Fatal("inline output bound not enforced")
	}
}
