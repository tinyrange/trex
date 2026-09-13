package msdelta

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPERestoreEmptyTargetDescriptorPreservesFinalImage(t *testing.T) {
	target := makeTimestampTestPE(0x11223344)
	put32(target, 0x40+24+64, 0x87654321)
	want := bytes.Clone(target)
	p := &pePreprocess{rebuildChecksum: true}
	if err := p.restore(target); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target, want) {
		t.Fatal("empty target descriptor changed final PE fields")
	}
}

func TestPERestoreDoesNotUseVirtualOnlySectionAsFileBoundary(t *testing.T) {
	const timestamp = 0x11223344
	target := append(makeTestPE32(0x10000000, 1, timestamp), make([]byte, 0x500)...)
	const sectionTable = 0x40 + 24 + 96
	binary.LittleEndian.PutUint16(target[0x40+6:], 4)
	sections := []struct {
		name                                string
		rva, virtualSize, rawStart, rawSize uint32
	}{
		{".text", 0x1000, 0x180, 0x200, 0x200},
		{".imrsiv", 0x2000, 4, 0, 0},
		{".data", 0x3000, 0x100, 0x400, 0x200},
		{".bss", 0x4000, 0x100, 0, 0},
	}
	for i, s := range sections {
		off := sectionTable + i*40
		copy(target[off:off+8], s.name)
		put32(target, off+8, s.virtualSize)
		put32(target, off+12, s.rva)
		put32(target, off+16, s.rawSize)
		put32(target, off+20, s.rawStart)
	}
	want := append([]byte(nil), target...)
	p := &pePreprocess{
		prefix:          peRestore{imageBase: 0x10000000, timestamp: timestamp},
		targetRVAtoFile: riftTable{entries: []riftEntry{{source: 0x1000, target: 0x200}, {source: 0x3000, target: 0x400}}},
	}
	if err := p.restore(target); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target, want) {
		t.Fatalf("restoration changed final section extents: .text size=%#x, .data size=%#x", get32(target, sectionTable+16), get32(target, sectionTable+80+16))
	}
}

func TestPERestorePreservesVirtualOnlySection(t *testing.T) {
	target := makeTimestampTestPE(0x11223344)
	optional := 0x40 + 24
	section := optional + 0xe0
	copy(target[section:section+8], []byte(".bss\x00\x00\x00\x00"))
	put32(target, section+16, 0)
	put32(target, section+20, 0)
	put32(target, section+36, 0xc0000080)
	p := &pePreprocess{
		prefix:          peRestore{imageBase: 0x10000000, timestamp: 0x55667788},
		targetRVAtoFile: riftTable{entries: []riftEntry{{source: 0x1000, target: 0x200}}},
		rebuildChecksum: true,
	}
	if err := p.restore(target); err != nil {
		t.Fatal(err)
	}
	if get32(target, section+16) != 0 || get32(target, section+20) != 0 {
		t.Fatal("restoration invented a raw extent for a virtual-only section")
	}
	checksum := get32(target, optional+64)
	put32(target, optional+64, 0)
	if checksum != peChecksum(target) {
		t.Fatal("restoration did not rebuild checksum over preserved section fields")
	}
}

func TestPERestorePreservesExplicitNonzeroChecksum(t *testing.T) {
	target := makeTimestampTestPE(0x11223344)
	const checksum = 0x87654321
	const checksumOffset = 0x40 + 24 + 64
	put32(target, checksumOffset, checksum)
	p := &pePreprocess{
		prefix:          peRestore{imageBase: 0x10000000, timestamp: 0x55667788},
		targetRVAtoFile: riftTable{entries: []riftEntry{{source: 0x1000, target: 0x200}}},
		rebuildChecksum: true,
	}
	if err := p.restore(target); err != nil {
		t.Fatal(err)
	}
	if get32(target, checksumOffset) != checksum {
		t.Fatal("restoration replaced the patch-supplied checksum")
	}
	if get32(target, 0x48) != 0x55667788 {
		t.Fatal("preserving checksum skipped timestamp restoration")
	}
}

func TestRestorePETimestampsCoversHeaderExportAndDebugData(t *testing.T) {
	const sourceTimestamp = 0x11223344
	const targetTimestamp = 0x55667788
	source := makeTimestampTestPE(sourceTimestamp)
	target := append([]byte(nil), source...)
	if err := restorePETimestamps(source, target, targetTimestamp); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0x48, 0x204, 0x244, 0x308} {
		if got := binary.LittleEndian.Uint32(target[offset:]); got != targetTimestamp {
			t.Fatalf("timestamp at %#x = %#x, want %#x", offset, got, uint32(targetTimestamp))
		}
	}
	if got := binary.LittleEndian.Uint32(target[0x350:]); got != sourceTimestamp {
		t.Fatalf("unrelated timestamp-like value changed to %#x", got)
	}
}

func makeTimestampTestPE(timestamp uint32) []byte {
	data := makeTestPE32(0x10000000, 0, timestamp)
	data = append(data, make([]byte, 0x400-len(data))...)
	optional := 0x40 + 24
	binary.LittleEndian.PutUint16(data[0x40+6:], 1)
	binary.LittleEndian.PutUint16(data[0x40+20:], 0xe0)
	binary.LittleEndian.PutUint32(data[optional+92:], 16)
	binary.LittleEndian.PutUint32(data[optional+96:], 0x1000)
	binary.LittleEndian.PutUint32(data[optional+100:], 40)
	binary.LittleEndian.PutUint32(data[optional+96+6*8:], 0x1040)
	binary.LittleEndian.PutUint32(data[optional+100+6*8:], 28)
	section := optional + 0xe0
	copy(data[section:], ".rdata")
	binary.LittleEndian.PutUint32(data[section+8:], 0x200)
	binary.LittleEndian.PutUint32(data[section+12:], 0x1000)
	binary.LittleEndian.PutUint32(data[section+16:], 0x200)
	binary.LittleEndian.PutUint32(data[section+20:], 0x200)
	binary.LittleEndian.PutUint32(data[0x204:], timestamp)
	binary.LittleEndian.PutUint32(data[0x244:], timestamp)
	binary.LittleEndian.PutUint32(data[0x240+16:], 0x20)
	binary.LittleEndian.PutUint32(data[0x240+24:], 0x300)
	binary.LittleEndian.PutUint32(data[0x308:], timestamp)
	binary.LittleEndian.PutUint32(data[0x350:], timestamp)
	return data
}
