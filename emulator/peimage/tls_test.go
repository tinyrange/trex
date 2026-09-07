package peimage

import (
	"debug/pe"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

func TestTLSNativePointerWidths(t *testing.T) {
	for _, width := range []int{4, 8} {
		base := uint64(0x400000)
		if width == 8 {
			base = 0x180000000
		}
		image := &Image{Base: base, Architecture: cpu.Architecture{PointerSize: width}, Data: make([]byte, 256)}
		image.Directories[9] = pe.DataDirectory{VirtualAddress: 16, Size: uint32(width*4 + 8)}
		pointer := func(offset int, value uint64) {
			if width == 4 {
				binary.LittleEndian.PutUint32(image.Data[offset:], uint32(value))
			} else {
				binary.LittleEndian.PutUint64(image.Data[offset:], value)
			}
		}
		pointer(16, base+128)
		pointer(16+width, base+131)
		pointer(16+width*2, base+144)
		pointer(16+width*3, base+160)
		binary.LittleEndian.PutUint32(image.Data[16+width*4:], 7)
		copy(image.Data[128:], []byte{1, 2, 3})
		pointer(160, base+200)
		tls, err := image.TLS()
		if err != nil || string(tls.Template) != "\x01\x02\x03" || tls.IndexAddress != base+144 || tls.ZeroFill != 7 || len(tls.Callbacks) != 1 || tls.Callbacks[0] != base+200 {
			t.Fatalf("width %d: %+v, %v", width, tls, err)
		}
		tls.Template[0] = 99
		if image.Data[128] != 1 {
			t.Fatal("TLS template aliases PE")
		}
		pointer(16+width, base+127)
		if _, err := image.TLS(); err == nil {
			t.Fatal("reversed template accepted")
		}
		pointer(16+width, base+131)
		pointer(16+width*3, base+255)
		if _, err := image.TLS(); err == nil {
			t.Fatal("truncated callback pointer accepted")
		}
		pointer(16+width*3, base+160)
		pointer(16+width*2, base+255)
		if _, err := image.TLS(); err == nil {
			t.Fatal("out-of-range index accepted")
		}
	}
}
