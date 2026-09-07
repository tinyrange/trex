package peimage

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"testing"
)

func testImage(t *testing.T, pointerSize int) []byte {
	t.Helper()
	data := make([]byte, 0x400)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	var headers bytes.Buffer
	headers.WriteString("PE\x00\x00")
	machine := uint16(pe.IMAGE_FILE_MACHINE_AMD64)
	var optional any = &pe.OptionalHeader64{Magic: 0x20b, ImageBase: 0x180000000, AddressOfEntryPoint: 0x1000, SizeOfImage: 0x2000, SizeOfHeaders: 0x200, SectionAlignment: 0x1000, FileAlignment: 0x200, NumberOfRvaAndSizes: 16}
	if pointerSize == 4 {
		machine = pe.IMAGE_FILE_MACHINE_I386
		optional = &pe.OptionalHeader32{Magic: 0x10b, ImageBase: 0x400000, AddressOfEntryPoint: 0x1000, SizeOfImage: 0x2000, SizeOfHeaders: 0x200, SectionAlignment: 0x1000, FileAlignment: 0x200, NumberOfRvaAndSizes: 16}
	}
	for _, value := range []any{
		pe.FileHeader{Machine: machine, NumberOfSections: 1, SizeOfOptionalHeader: uint16(binary.Size(optional)), Characteristics: pe.IMAGE_FILE_EXECUTABLE_IMAGE},
		optional,
		pe.SectionHeader32{Name: [8]byte{'.', 't', 'e', 'x', 't'}, VirtualSize: 0x10, VirtualAddress: 0x1000, SizeOfRawData: 0x200, PointerToRawData: 0x200, Characteristics: 0x60000020},
	} {
		if err := binary.Write(&headers, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	copy(data[0x80:], headers.Bytes())
	data[0x200] = 0xc3
	return data
}

func TestParseBothPointerWidths(t *testing.T) {
	for _, width := range []int{4, 8} {
		image, err := Parse(testImage(t, width), 0x2000)
		if err != nil {
			t.Fatal(err)
		}
		if image.Architecture.PointerSize != width || len(image.Data) != 0x2000 || image.Data[0x1000] != 0xc3 {
			t.Fatalf("bad mapped image: %#v", image.Architecture)
		}
		if width == 8 && image.Base != 0x180000000 {
			t.Fatalf("base truncated: %#x", image.Base)
		}
		if _, err := Parse(testImage(t, width), 0x1000); err == nil {
			t.Fatal("budget ignored")
		}
	}
}

func TestParseRejectsMachineHeaderMismatch(t *testing.T) {
	data := testImage(t, 8)
	binary.LittleEndian.PutUint16(data[0x84:], pe.IMAGE_FILE_MACHINE_I386)
	if _, err := Parse(data, 0x2000); err == nil {
		t.Fatal("mismatched machine accepted")
	}
}

func relocationImage(kind uint16) ([]byte, pe.DataDirectory) {
	data := make([]byte, 0x1000)
	directory := pe.DataDirectory{VirtualAddress: 0x100, Size: 12}
	binary.LittleEndian.PutUint32(data[0x100:], 0)
	binary.LittleEndian.PutUint32(data[0x104:], 12)
	binary.LittleEndian.PutUint16(data[0x108:], kind<<12|0x200)
	return data, directory
}

func TestDIR64RelocationBothDirections(t *testing.T) {
	for _, bases := range [][2]uint64{{0x180000000, 0x280000000}, {0x280000000, 0x180000000}} {
		data, directory := relocationImage(10)
		binary.LittleEndian.PutUint64(data[0x200:], bases[0]+0x1234)
		if err := Relocate(data, directory, bases[0], bases[1], 8); err != nil {
			t.Fatal(err)
		}
		if got := binary.LittleEndian.Uint64(data[0x200:]); got != bases[1]+0x1234 {
			t.Fatalf("relocation=%#x", got)
		}
	}
}

func TestInvalidRelocationsDoNotPartiallyModifyImage(t *testing.T) {
	data, directory := relocationImage(10)
	binary.LittleEndian.PutUint64(data[0x200:], 0x180002000)
	binary.LittleEndian.PutUint16(data[0x10a:], 10<<12|0xffc)
	before := bytes.Clone(data)
	if err := Relocate(data, directory, 0x180000000, 0x280000000, 8); err == nil {
		t.Fatal("out-of-range DIR64 accepted")
	}
	if !bytes.Equal(data, before) {
		t.Fatal("failed relocation changed image")
	}
	if err := Relocate(data, directory, 0x400000, 0x800000, 4); err == nil {
		t.Fatal("DIR64 in PE32 accepted")
	}
}
