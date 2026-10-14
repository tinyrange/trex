package udf

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func bootFixture() []byte {
	b := make([]byte, 80*2048)
	copy(b[16*2048+1:], "BEA01")
	d := b[18*2048 : 19*2048]
	copy(d[1:], "BOOT2")
	d[6] = 1
	copy(d[9:], "test architecture")
	copy(d[41:], "test bootstrap")
	binary.LittleEndian.PutUint32(d[72:], 64)
	binary.LittleEndian.PutUint32(d[76:], 4096)
	binary.LittleEndian.PutUint64(d[80:], 0x123456789abcdef0)
	binary.LittleEndian.PutUint64(d[88:], 0x100000004)
	copy(b[19*2048+1:], "TEA01")
	copy(b[64*2048:], "boot payload")
	return b
}

func TestBootExtentAndVirtualViews(t *testing.T) {
	raw := bootFixture()
	source := &starfile.Bytes{Data: raw}
	descriptors, err := ReadBootDescriptors(source)
	if err != nil || len(descriptors) != 1 {
		t.Fatal(descriptors, err)
	}
	d := descriptors[0]
	if d.ExtentOffset != 64*2048 || d.ExtentBytes != 4096 || d.LoadAddress != 0x123456789abcdef0 || d.StartAddress != 0x100000004 || d.Architecture != "test architecture" {
		t.Fatal(d)
	}
	img := &udfImage{file: source, bootDescriptors: descriptors}
	f := img.virtualFile("/$metadata/boot0.extent.bin")
	h := make([]byte, 12)
	if _, err := f.ReadAt(h, 0); err != nil || string(h) != "boot payload" {
		t.Fatal(string(h), err)
	}
	info := img.virtualFile("/$metadata/boot0.json")
	text := make([]byte, info.Size())
	if _, err := info.ReadAt(text, 0); err != nil {
		t.Fatal(err)
	}
	var decoded BootDescriptor
	if err := json.Unmarshal(text, &decoded); err != nil || decoded != d {
		t.Fatal(decoded, err)
	}
}

func TestBootDescriptorRejectsMalformedAndUnbounded(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"version":               func(b []byte) []byte { b[18*2048+6] = 2; return b },
		"reserved":              func(b []byte) []byte { b[18*2048+110] = 1; return b },
		"extent outside":        func(b []byte) []byte { binary.LittleEndian.PutUint32(b[18*2048+72:], 0xffffffff); return b },
		"length outside":        func(b []byte) []byte { binary.LittleEndian.PutUint32(b[18*2048+76:], 0xffffffff); return b },
		"truncated sequence":    func(b []byte) []byte { return b[:19*2048] },
		"unterminated sequence": func(b []byte) []byte { clear(b[19*2048 : 20*2048]); return b },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadBootDescriptors(&starfile.Bytes{Data: mutate(bootFixture())}); err == nil {
				t.Fatal("accepted malformed boot metadata")
			}
		})
	}
}

func TestBootDescriptorDoesNotCarvePayloads(t *testing.T) {
	b := bootFixture()
	clear(b[16*2048 : 17*2048])
	// A BOOT2-like record without a recognition sequence is not a descriptor.
	d, err := ReadBootDescriptors(&starfile.Bytes{Data: b})
	if err != nil || len(d) != 0 {
		t.Fatal(d, err)
	}
	b = bootFixture()
	clear(b[18*2048 : 19*2048])
	d, err = ReadBootDescriptors(&starfile.Bytes{Data: b})
	if err != nil || len(d) != 0 {
		t.Fatal(d, err)
	}
	if !bytes.Equal(b[64*2048:64*2048+12], []byte("boot payload")) {
		t.Fatal("source modified")
	}
}
