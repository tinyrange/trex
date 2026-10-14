package macho

import (
	"encoding/binary"
	"testing"
)

func exportTrieFixture() []byte {
	names := []string{"_regular", "_absolute", "_stub", "_forward"}
	terminals := [][]byte{{0, 0xa3, 2}, {2, 0x77}, {0x10, 0x22, 0x44}, {8, 2, '_', 'd', 'e', 'p', 0}}
	root := []byte{0, 4}
	for _, name := range names {
		root = append(root, []byte(name)...)
		root = append(root, 0, 0)
	}
	result := append([]byte(nil), root...)
	pos := 2
	for i, name := range names {
		pos += len(name) + 1
		result[pos] = byte(len(result))
		pos++
		result = append(result, byte(len(terminals[i])))
		result = append(result, terminals[i]...)
		result = append(result, 0)
	}
	return result
}

func TestExportTrieTerminalsAndLoadCommands(t *testing.T) {
	trie := exportTrieFixture()
	for _, legacy := range []bool{false, true} {
		commandSize := 16
		if legacy {
			commandSize = 48
		}
		offset := 32 + 72 + commandSize
		b := make(source, offset+len(trie))
		u32, u64 := binary.LittleEndian.PutUint32, binary.LittleEndian.PutUint64
		u32(b, 0xfeedfacf)
		u32(b[4:], ARM64)
		u32(b[12:], 2)
		u32(b[16:], 2)
		u32(b[20:], uint32(72+commandSize))
		seg := b[32:]
		u32(seg, 0x19)
		u32(seg[4:], 72)
		copy(seg[8:], "__TEXT")
		u64(seg[24:], 0x100000000)
		u64(seg[32:], uint64(len(b)))
		u64(seg[48:], uint64(len(b)))
		cmd := b[104:]
		u32(cmd, 0x80000033)
		u32(cmd[4:], 16)
		field := 8
		if legacy {
			u32(cmd, 0x80000022)
			u32(cmd[4:], 48)
			field = 40
		}
		u32(cmd[field:], uint32(offset))
		u32(cmd[field+4:], uint32(len(trie)))
		copy(b[offset:], trie)
		image, err := Open(b, ARM64)
		if err != nil {
			t.Fatal(err)
		}
		e := image.Exports
		if len(e) != 4 || e[0].Name != "_regular" || e[0].Address != 0x100000123 || e[1].Address != 0x77 || e[2].Address != 0x100000022 || e[2].Resolver != 0x100000044 || e[3].ReexportOrdinal != 2 || e[3].ImportName != "_dep" {
			t.Fatalf("exports=%+v", e)
		}
	}
}

func TestExportTrieRejectsMalformedGraphsAndNumbers(t *testing.T) {
	for _, b := range [][]byte{
		{0, 1, 'x', 0, 0},  // cycle
		{0, 1, 'x', 0, 99}, // missing child
		{0, 1, 0, 4, 0},    // empty edge
		{1, 0, 0},          // missing terminal address
		{0x80},             // unterminated terminal length
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2}, // ULEB overflow
	} {
		if _, err := readExports(b, 0); err == nil {
			t.Fatalf("accepted %x", b)
		}
	}
}
