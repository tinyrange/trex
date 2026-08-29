package fat

import (
	"encoding/binary"
	"testing"
)

func TestFAT12And16IgnoreDirectoryClusterHighWord(t *testing.T) {
	entry := make([]byte, 64)
	copy(entry[:11], []byte("QBASIC  EX_"))
	binary.LittleEndian.PutUint16(entry[20:22], 0x0c09)
	binary.LittleEndian.PutUint16(entry[26:28], 0x0123)
	for _, fatType := range []int{12, 16} {
		entries := parseFATDirectory(entry, "/", fatType)
		if len(entries) != 1 || entries[0].cluster != 0x0123 {
			t.Fatalf("FAT%d cluster = %#x, want %#x", fatType, entries[0].cluster, 0x0123)
		}
	}
	entries := parseFATDirectory(entry, "/", 32)
	if len(entries) != 1 || entries[0].cluster != 0x0c090123 {
		t.Fatalf("FAT32 cluster = %#x, want %#x", entries[0].cluster, 0x0c090123)
	}
}
