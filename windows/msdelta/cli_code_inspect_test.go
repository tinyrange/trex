package msdelta

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func inspectionFixture(t *testing.T) []byte {
	data, _ := makeTestCLIImage(t)
	table := bytes.Clone(data[0x2b0:0x2da])
	clear(data[0x298:0x480])
	put32(data, 0x20c, 0x200)
	put32(data, 0x214, 0x06000001)
	binary.LittleEndian.PutUint16(data[0x296:], 4)
	off := 0x298
	for _, s := range []struct {
		name      string
		pos, size int
	}{{"#~", 0x300, 42}, {"#Strings", 0x3a0, 6}, {"#US", 0x3c0, 7}, {"#Blob", 0x3e0, 5}} {
		put32(data, off, uint32(s.pos-0x280))
		put32(data, off+4, uint32(s.size))
		copy(data[off+8:], s.name)
		off = (off + 8 + len(s.name) + 4) &^ 3
	}
	copy(data[0x300:], table)
	binary.LittleEndian.PutUint16(data[0x324:], 1) // MethodDef.Name
	binary.LittleEndian.PutUint16(data[0x326:], 1) // MethodDef.Signature
	copy(data[0x3a0:], []byte{0, 'M', 'a', 'i', 'n', 0})
	copy(data[0x3c0:], []byte{0, 5, 'H', 0, 'i', 0, 0})
	copy(data[0x3e0:], []byte{0, 3, 0, 0, 1})
	data[0x500] = byte(7<<2 | 2)
	copy(data[0x501:], []byte{0x72, 1, 0, 0, 0x70, 0x26, 0x2a})
	return data
}

func TestCLIInspectionNamesStringsAndIL(t *testing.T) {
	data := inspectionFixture(t)
	original := bytes.Clone(data)
	info, err := InspectCLI(data, "Main")
	if err != nil {
		t.Fatal(err)
	}
	if info.EntryPoint != 0x06000001 || len(info.Methods) != 1 || info.Methods[0].Name != "Main" {
		t.Fatalf("unexpected entry/method: %+v", info)
	}
	if info.RuntimeVersion != "v4" || info.CorFlags != 1 {
		t.Fatalf("runtime/header metadata: %+v", info)
	}
	if info.Strings[0x70000001] != "Hi" {
		t.Fatalf("strings: %v", info.Strings)
	}
	ins := info.Methods[0].Instructions
	if len(ins) != 3 || ins[0].Token != 0x70000001 || ins[1].Offset != 5 || ins[2].Opcode != 0x2a {
		t.Fatalf("instructions: %+v", ins)
	}
	if !bytes.Equal(info.Rows[0].Columns[4].([]byte), []byte{0, 0, 1}) {
		t.Fatal("signature not decoded")
	}
	filtered, err := InspectCLI(data, "Missing")
	if err != nil || len(filtered.Methods) != 0 || len(filtered.Rows) != 1 {
		t.Fatalf("filter: %+v %v", filtered, err)
	}
	if !bytes.Equal(data, original) {
		t.Fatal("inspection mutated source")
	}
}

func TestCLIInspectionMalformedBounds(t *testing.T) {
	original := inspectionFixture(t)
	for n := 0; n < 0x508; n++ {
		if _, err := InspectCLI(original[:n], ""); err == nil {
			t.Fatalf("accepted truncated PE %d", n)
		}
	}
	for _, test := range []struct {
		name   string
		offset int
		value  byte
	}{
		{"string", 0x324, 255}, {"blob", 0x326, 255}, {"unterminated string", 0x3a5, 'x'},
		{"user string length", 0x3c1, 127}, {"odd UTF16", 0x3c1, 4}, {"method body", 0x500, 255},
		{"reserved opcode", 0x501, 0x24},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := bytes.Clone(original)
			data[test.offset] = test.value
			if _, err := InspectCLI(data, ""); err == nil {
				t.Fatal("accepted malformed metadata/code")
			}
		})
	}
}

func TestCLIInspectionOperandBoundaries(t *testing.T) {
	for _, code := range [][]byte{{0xfe}, {0x72, 0, 0}, {0x20, 1}, {0xfe, 0x09, 0}, {0x45, 255, 255, 255, 255}, {0x24}} {
		if _, err := inspectCLIInstructions(code); err == nil {
			t.Fatalf("accepted malformed IL %x", code)
		}
	}
	code := []byte{0x45, 2, 0, 0, 0, 1, 0, 0, 0, 255, 255, 255, 255, 0xfe, 0x09, 1, 0, 0x2a}
	ins, err := inspectCLIInstructions(code)
	if err != nil {
		t.Fatal(err)
	}
	if len(ins) != 3 || ins[1].Offset != 13 || ins[2].Offset != 17 {
		t.Fatalf("switch/extended operand boundaries: %+v", ins)
	}
}
