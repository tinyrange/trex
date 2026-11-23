package mipscoff

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func legacyMessageTable() []byte {
	le := binary.LittleEndian
	// The second payload is already four-byte aligned. Its NUL still
	// needs its own padding, so that entry occupies twelve bytes.
	table := make([]byte, 44)
	le.PutUint32(table, 1)
	le.PutUint32(table[4:], 9000)
	le.PutUint32(table[8:], 9001)
	le.PutUint32(table[12:], 16)
	le.PutUint16(table[16:], 11)
	le.PutUint16(table[18:], 1)
	copy(table[20:], "Y N A R I\r\n")
	le.PutUint16(table[32:], 4)
	le.PutUint16(table[34:], 2)
	copy(table[36:], "Test")
	return table
}

func TestMessageLengthPatchesPreservePayloadAndAcceptCorrectedTable(t *testing.T) {
	table := legacyMessageTable()
	const fileOffset = 0x1b630
	patches, err := messageLengthPatches(table, fileOffset)
	want := []MessageLengthPatch{{fileOffset + 16, 11, 16}, {fileOffset + 32, 4, 12}}
	if err != nil || !reflect.DeepEqual(patches, want) {
		t.Fatalf("message patches %+v, %v, want %+v", patches, err, want)
	}
	for _, patch := range patches {
		binary.LittleEndian.PutUint16(table[patch.Offset-fileOffset:], patch.After)
	}
	if patches, err = messageLengthPatches(table, fileOffset); err != nil || len(patches) != 0 {
		t.Fatalf("corrected table produced patches %+v, %v", patches, err)
	}
	if got := string(table[20:31]); got != "Y N A R I\r\n" || string(table[36:40]) != "Test" {
		t.Fatalf("message bytes changed: %q", got)
	}
}

func TestMalformedLegacyMessageTableHasNoPatches(t *testing.T) {
	table := legacyMessageTable()
	table[31] = 'x'
	if patches, err := messageLengthPatches(table, 0); err == nil || len(patches) != 0 {
		t.Fatalf("accepted a missing terminator: %+v, %v", patches, err)
	}
	if patches, err := messageLengthPatches(legacyMessageTable()[:43], 0); err == nil || len(patches) != 0 {
		t.Fatalf("accepted truncated padding: %+v, %v", patches, err)
	}
}
