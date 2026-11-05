package windows

import (
	"encoding/binary"
	"testing"
)

func neReferenceFixture(t *testing.T) ([]byte, int, int) {
	t.Helper()
	data, err := extendWindowsNE(neExportFixture(), []byte{0x90, 0x90, 0xff, 0xff, 0x90, 0x90, 0xff, 0xff}, []byte{0}, []neInternalRelocation{{2, 2, -1, 0}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseWindowsNEModule(data)
	if err != nil {
		t.Fatal(err)
	}
	base := int(binary.LittleEndian.Uint16(data[m.segments+16:])) << m.alignShift
	binary.LittleEndian.PutUint16(data[base+2:], 6)
	return data, base, base + 8 + 2
}

func TestNEInternalReferencesExpandChainsAndResolveEntries(t *testing.T) {
	data, base, fixup := neReferenceFixture(t)
	refs, err := parseNEInternalReferences(data, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 || refs[0].Offset != 2 || refs[1].Offset != 6 || refs[0].Segment != 3 || refs[0].TargetSegment != 4 || refs[0].SourceType != 2 || refs[0].Additive {
		t.Fatalf("references=%+v", refs)
	}
	data[fixup+4] = 255
	binary.LittleEndian.PutUint16(data[fixup+6:], 1)
	refs, err = parseNEInternalReferences(data, 10)
	if err != nil {
		t.Fatal(err)
	}
	if refs[0].TargetOrdinal != 1 || refs[0].TargetSegment != 1 || refs[0].TargetOffset != 7 {
		t.Fatalf("entry reference=%+v", refs[0])
	}
	data[fixup+1] = 4
	binary.LittleEndian.PutUint16(data[base+2:], 1234)
	refs, err = parseNEInternalReferences(data, 10)
	if err != nil || len(refs) != 1 || !refs[0].Additive {
		t.Fatalf("additive=%+v error=%v", refs, err)
	}
}

func TestNEInternalReferencesRejectInvalidChainsAndLimits(t *testing.T) {
	for _, kind := range []string{"cycle", "link", "target", "entry", "source", "limit"} {
		t.Run(kind, func(t *testing.T) {
			data, base, fixup := neReferenceFixture(t)
			maximum := 10
			switch kind {
			case "cycle":
				binary.LittleEndian.PutUint16(data[base+6:], 2)
			case "link":
				binary.LittleEndian.PutUint16(data[base+6:], 7)
			case "target":
				data[fixup+4] = 5
			case "entry":
				data[fixup+4] = 255
				binary.LittleEndian.PutUint16(data[fixup+6:], 2)
			case "source":
				data[fixup] = 7
			case "limit":
				maximum = 1
			}
			if _, err := parseNEInternalReferences(data, maximum); err == nil {
				t.Fatal("accepted invalid reference")
			}
		})
	}
}

func TestNEInternalReferencesAllowZeroFilledSegmentTail(t *testing.T) {
	data, base, fixup := neReferenceFixture(t)
	module, err := parseWindowsNEModule(data)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint16(data[module.segments+16+6:], 16)
	data[fixup+1] = 4
	binary.LittleEndian.PutUint16(data[fixup+2:], 14)
	refs, err := parseNEInternalReferences(data, 10)
	if err != nil || len(refs) != 1 || refs[0].Offset != 14 || !refs[0].Additive {
		t.Fatal(refs, err)
	}
	binary.LittleEndian.PutUint16(data[fixup+2:], 15)
	if _, err := parseNEInternalReferences(data, 10); err == nil {
		t.Fatal("fixup crossed segment allocation")
	}
	// A nonadditive tail link sees the loader's zeros, not the following
	// relocation table. It can link to the stored terminator at offset zero.
	data[fixup+1] = 0
	binary.LittleEndian.PutUint16(data[fixup+2:], 14)
	binary.LittleEndian.PutUint16(data[base:], 0xffff)
	refs, err = parseNEInternalReferences(data, 10)
	if err != nil || len(refs) != 2 || refs[1].Offset != 0 {
		t.Fatal(refs, err)
	}
}
