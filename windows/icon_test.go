package windows

import (
	"encoding/binary"
	"testing"
)

func TestWindowsIconSelectsICOEntryByIndex(t *testing.T) {
	data := make([]byte, 6+2*16+7)
	binary.LittleEndian.PutUint16(data[2:4], 1)
	binary.LittleEndian.PutUint16(data[4:6], 2)
	data[6], data[7] = 16, 16
	binary.LittleEndian.PutUint16(data[12:14], 1)
	binary.LittleEndian.PutUint32(data[14:18], 3)
	binary.LittleEndian.PutUint32(data[18:22], 38)
	data[22], data[23] = 32, 32
	binary.LittleEndian.PutUint16(data[28:30], 4)
	binary.LittleEndian.PutUint32(data[30:34], 4)
	binary.LittleEndian.PutUint32(data[34:38], 41)
	copy(data[38:], []byte{1, 2, 3, 4, 5, 6, 7})

	icon, err := windowsIcon(data, 1, 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	if icon.width != 32 || icon.height != 32 || icon.bitsPerPixel != 4 {
		t.Fatalf("unexpected icon metadata: %+v", icon)
	}
	if got, want := icon.data, []byte{4, 5, 6, 7}; string(got) != string(want) {
		t.Fatalf("icon data = %v, want %v", got, want)
	}
}

func TestWindowsIconReadsNEResources(t *testing.T) {
	data := make([]byte, 0x180)
	copy(data[:2], "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:0x40], 0x40)
	copy(data[0x40:0x42], "NE")
	binary.LittleEndian.PutUint16(data[0x64:0x66], 0x40)
	binary.LittleEndian.PutUint16(data[0x66:0x68], 0x80)

	resourceTable := 0x80
	cursor := resourceTable + 2
	writeType := func(typ uint16, offset, length, id uint16) {
		binary.LittleEndian.PutUint16(data[cursor:cursor+2], 0x8000|typ)
		binary.LittleEndian.PutUint16(data[cursor+2:cursor+4], 1)
		cursor += 8
		binary.LittleEndian.PutUint16(data[cursor:cursor+2], offset)
		binary.LittleEndian.PutUint16(data[cursor+2:cursor+4], length)
		binary.LittleEndian.PutUint16(data[cursor+6:cursor+8], 0x8000|id)
		cursor += 12
	}
	writeType(14, 0x100, 20, 1)
	writeType(3, 0x140, 4, 2)
	binary.LittleEndian.PutUint16(data[cursor:cursor+2], 0)

	group := data[0x100:0x114]
	binary.LittleEndian.PutUint16(group[2:4], 1)
	binary.LittleEndian.PutUint16(group[4:6], 1)
	group[6], group[7] = 32, 32
	binary.LittleEndian.PutUint16(group[12:14], 4)
	binary.LittleEndian.PutUint32(group[14:18], 4)
	binary.LittleEndian.PutUint16(group[18:20], 2)
	copy(data[0x140:0x144], []byte{0xde, 0xad, 0xbe, 0xef})

	icon, err := windowsIcon(data, 0, 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	if icon.resourceID != 2 || icon.resourceType != 3 || icon.bitsPerPixel != 4 {
		t.Fatalf("unexpected icon metadata: %+v", icon)
	}
	if got, want := icon.data, []byte{0xde, 0xad, 0xbe, 0xef}; string(got) != string(want) {
		t.Fatalf("icon data = %x, want %x", got, want)
	}
}
