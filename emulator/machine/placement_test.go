package machine

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/emulator/amd64"
	"github.com/tinyrange/trex/emulator/cpu"
)

func relocatableFixture(t *testing.T, relocatable bool) []byte {
	t.Helper()
	const base = 0x7ff5fce0000
	optional := pe.OptionalHeader64{Magic: 0x20b, ImageBase: base, AddressOfEntryPoint: 0x1000, SizeOfImage: 0x2000, SizeOfHeaders: 0x200, SectionAlignment: 4096, FileAlignment: 512, NumberOfRvaAndSizes: 16}
	if relocatable {
		optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC] = pe.DataDirectory{VirtualAddress: 0x1100, Size: 12}
	}
	optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_TLS] = pe.DataDirectory{VirtualAddress: 0x1140, Size: 40}
	var headers bytes.Buffer
	headers.WriteString("PE\x00\x00")
	for _, value := range []any{
		pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_AMD64, NumberOfSections: 1, SizeOfOptionalHeader: uint16(binary.Size(optional)), Characteristics: pe.IMAGE_FILE_EXECUTABLE_IMAGE | pe.IMAGE_FILE_DLL},
		optional,
		pe.SectionHeader32{Name: [8]byte{'.', 't', 'e', 'x', 't'}, VirtualSize: 0x200, VirtualAddress: 0x1000, SizeOfRawData: 0x200, PointerToRawData: 0x200, Characteristics: 0x60000020},
	} {
		if err := binary.Write(&headers, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	data := make([]byte, 0x400)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], headers.Bytes())
	data[0x200] = 0xc3
	binary.LittleEndian.PutUint32(data[0x300:], 0x1000)
	binary.LittleEndian.PutUint32(data[0x304:], 12)
	// Relocate a pointer in .text and the TLS index VA.
	binary.LittleEndian.PutUint16(data[0x308:], 0xa080)
	binary.LittleEndian.PutUint16(data[0x30a:], 0xa150)
	binary.LittleEndian.PutUint64(data[0x280:], base+0x1000)
	binary.LittleEndian.PutUint64(data[0x350:], base+0x1190)
	return data
}

func TestCollidingModuleRelocation(t *testing.T) {
	m := &Machine{processor: &amd64.CPU{}, memory: cpu.NewAddressSpace(1 << 20), memoryLimit: 1 << 20, imports: make(map[uint64]imported)}
	data := relocatableFixture(t, true)
	original := bytes.Clone(data)
	first, err := m.load(data, "first.dll")
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.load(data, "second.dll")
	if err != nil {
		t.Fatal(err)
	}
	third, err := m.load(data, "third.dll")
	if err != nil {
		t.Fatal(err)
	}
	if first.image.Base != first.image.PreferredBase || second.image.Base == first.image.Base || third.image.Base == second.image.Base || second.image.Base%0x10000 != 0 {
		t.Fatal("module placement did not preserve preferred base and find distinct aligned gaps")
	}
	for _, loaded := range []module{first, second, third} {
		var pointer [8]byte
		if err := m.memory.ReadMemory(loaded.image.Base+0x1080, pointer[:], cpu.Read); err != nil {
			t.Fatal(err)
		}
		if binary.LittleEndian.Uint64(pointer[:]) != loaded.image.Base+0x1000 || loaded.tls.IndexAddress != loaded.image.Base+0x1190 {
			t.Fatal("relocation or post-relocation TLS parsing lost native address")
		}
	}
	if !bytes.Equal(data, original) {
		t.Fatal("source PE modified")
	}
	before := len(m.memory.Mappings())
	if _, err := m.load(relocatableFixture(t, false), "fixed.dll"); err == nil {
		t.Fatal("accepted collision without relocations")
	}
	if len(m.modules) != 3 || len(m.memory.Mappings()) != before {
		t.Fatal("failed load left partial state")
	}
}
