package os2

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

func TestLXImportModuleBounds(t *testing.T) {
	original := lxFixture()
	h := original[0x80:]
	binary.LittleEndian.PutUint32(h[0x70:], 0x180)
	binary.LittleEndian.PutUint32(h[0x74:], 2)
	names := []byte("\x08DOSCALLS\x07so32dll")
	binary.LittleEndian.PutUint32(h[0x78:], 0x180+uint32(len(names)))
	copy(h[0x180:], names)
	image, err := DecodeLX(original, 1<<20)
	if err != nil || !reflect.DeepEqual(image.Imports, []string{"DOSCALLS", "so32dll"}) {
		t.Fatalf("imports: %+v %v", image, err)
	}
	for name, mutate := range map[string]func([]byte){
		"count":          func(h []byte) { binary.LittleEndian.PutUint32(h[0x74:], 65536) },
		"header-alias":   func(h []byte) { binary.LittleEndian.PutUint32(h[0x70:], 0x10) },
		"reverse":        func(h []byte) { binary.LittleEndian.PutUint32(h[0x78:], 0x170) },
		"truncated-name": func(h []byte) { h[0x180] = 255 },
		"empty":          func(h []byte) { h[0x180] = 0 },
		"embedded-nul":   func(h []byte) { h[0x182] = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			data := bytes.Clone(original)
			mutate(data[0x80:])
			if _, err := DecodeLX(data, 1<<20); err == nil {
				t.Fatal("invalid imports accepted")
			}
		})
	}
}
