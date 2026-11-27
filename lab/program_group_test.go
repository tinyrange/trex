package lab

import (
	"encoding/binary"
	"testing"
)

func TestWindows31ProgramGroup(t *testing.T) {
	const xorStart = 40 + 64
	const andStart = xorStart + 512
	dib := make([]byte, andStart+128)
	for index, value := range []uint32{40, 32, 64, 0x00040001} {
		binary.LittleEndian.PutUint32(dib[index*4:], value)
	}
	dib[xorStart+31*16] = 0x12
	dib[andStart+31*4] = 0x34
	item := programItem{name: "Visual Basic 3.0", command: `C:\VB\VB.EXE`, iconPath: `C:\VB\VB.EXE`, icon: dib}
	data, err := encodeProgramGroup("Visual Basic", []programItem{item}, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	word := func(offset int) int { return int(binary.LittleEndian.Uint16(data[offset:])) }
	if string(data[:4]) != "PMCC" || word(6) != len(data) || word(8) != 1 || word(32) != 1 {
		t.Fatalf("invalid Windows 3.1 group header: %x", data[:36])
	}
	pos := word(34)
	if name := word(pos + 18); string(data[name:name+len(item.name)+1]) != item.name+"\x00" {
		t.Fatal("item name is missing")
	}
	if cmd := word(pos + 20); string(data[cmd:cmd+len(item.command)+1]) != item.command+"\x00" {
		t.Fatal("item command is missing")
	}
	if word(pos+8) != 128 || word(pos+10) != 512 || data[word(pos+14)] != 0x34 || data[word(pos+16)] != 0x12 {
		t.Fatal("incorrect top-down icon masks")
	}
	var sum uint16
	for i := 0; i < len(data); i += 2 {
		sum += uint16(word(i))
	}
	if sum != 0 {
		t.Fatalf("invalid checksum: %#x", sum)
	}
}
