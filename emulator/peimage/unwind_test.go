package peimage

import (
	"debug/pe"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

func unwindFixture() *Image {
	i := &Image{Architecture: cpu.Architecture{Name: "amd64", PointerSize: 8}, Data: make([]byte, 1024)}
	i.Directories[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION] = pe.DataDirectory{VirtualAddress: 0x200, Size: 12}
	for offset, value := range map[int]uint32{0x200: 0x40, 0x204: 0xa0, 0x208: 0x220, 0x230: 0xb0, 0x234: 2, 0x238: 0x50, 0x23c: 0x70, 0x240: 0xc0, 0x244: 0, 0x248: 0x80, 0x24c: 0x90, 0x250: 1, 0x254: 0x98} {
		binary.LittleEndian.PutUint32(i.Data[offset:], value)
	}
	copy(i.Data[0x220:], []byte{0x11, 14, 5, 0, 14, 0x74, 11, 0, 9, 0x34, 10, 0, 4, 0x62, 0, 0})
	return i
}

func TestAMD64UnwindInfoAndScopes(t *testing.T) {
	i := unwindFixture()
	info, err := i.AMD64UnwindInfo(0x60)
	if err != nil {
		t.Fatal(err)
	}
	if info.Function.Begin != 0x40 || info.Flags != 2 || info.PrologSize != 14 || len(info.Codes) != 10 || info.Handler != 0xb0 || info.HandlerData != 0x234 {
		t.Fatalf("unexpected unwind metadata: %+v", info)
	}
	info.Codes[0] = 0
	if i.Data[0x224] != 14 {
		t.Fatal("unwind code view aliases image")
	}
	scopes, err := i.CScopes(info.HandlerData)
	if err != nil || len(scopes) != 2 || scopes[0] != (CScope{0x50, 0x70, 0xc0, 0}) || scopes[1].Handler != 1 {
		t.Fatalf("scopes=%+v, %v", scopes, err)
	}
	for _, rva := range []uint32{0x3f, 0xa0} {
		if result, err := i.AMD64UnwindInfo(rva); err != nil || result != nil {
			t.Fatal("outside function did not produce leaf")
		}
	}
}

func TestAMD64UnwindRejectsMalformedTables(t *testing.T) {
	for name, change := range map[string]func(*Image){
		"architecture":    func(i *Image) { i.Architecture.Name = "x86" },
		"directory size":  func(i *Image) { i.Directories[3].Size = 13 },
		"directory range": func(i *Image) { i.Directories[3].VirtualAddress = 1020 },
		"empty function":  func(i *Image) { binary.LittleEndian.PutUint32(i.Data[0x204:], 0x40) },
		"version":         func(i *Image) { i.Data[0x220] = 0x12 },
		"flags":           func(i *Image) { i.Data[0x220] = 0x39 },
		"code range": func(i *Image) {
			binary.LittleEndian.PutUint32(i.Data[0x208:], 1020)
			copy(i.Data[1020:], []byte{1, 0, 2, 0})
		},
		"handler": func(i *Image) { binary.LittleEndian.PutUint32(i.Data[0x230:], 1024) },
	} {
		t.Run(name, func(t *testing.T) {
			i := unwindFixture()
			change(i)
			if _, err := i.AMD64UnwindInfo(0x60); err == nil {
				t.Fatal("accepted malformed unwind data")
			}
		})
	}
	for _, test := range []struct {
		offset int
		value  uint32
	}{{0x234, 4097}, {0x238, 0x70}, {0x240, 0}, {0x240, 1024}, {0x254, 1024}} {
		i := unwindFixture()
		binary.LittleEndian.PutUint32(i.Data[test.offset:], test.value)
		if _, err := i.CScopes(0x234); err == nil {
			t.Fatal("accepted malformed C scope")
		}
	}
}
