package msdelta

import "testing"

func TestInspectCLISignatureReferencesPreservesSharedContexts(t *testing.T) {
	for _, width := range []uint8{2, 4} {
		source := make([]byte, 128)
		m := &cliMetadata{CLIPreprocessInfo: &CLIPreprocessInfo{HeapWidths: [3]uint8{2, 2, width}}}
		m.Streams[2] = CLIStreamInfo{Offset: 64, Size: 32}
		m.Rows[4], m.Rows[27] = 1, 1
		m.rowSizes[4], m.rowSizes[27] = 4+int(width), int(width)
		m.tableOffsets[27] = 16
		put16(source, 4, 1)
		put16(source, 16, 1)
		copy(source[65:], []byte{8, 0x20, 0x81, 0xb1, 0x20, 0x82, 0x91, 0x12, 0x3d})
		refs := inspectCLISignatureReferences(source, m, 71, 72)
		if len(refs) != 2 || refs[0].Table != 4 || refs[1].Table != 27 {
			t.Fatalf("width %d lost shared consumers or row order: %#v", width, refs)
		}
		for _, ref := range refs {
			if ref.Row != 1 || ref.BlobIndex != 1 || ref.Offset != 66 || ref.Size != 8 {
				t.Fatalf("wrong signature coordinates: %#v", ref)
			}
		}
		if refs := inspectCLISignatureReferences(source, m, 74, 75); len(refs) != 0 {
			t.Fatalf("non-overlapping signatures: %#v", refs)
		}
		source[65] = 127 // extent exceeds the blob heap
		if refs := inspectCLISignatureReferences(source, m, 71, 72); len(refs) != 0 {
			t.Fatalf("accepted truncated blob: %#v", refs)
		}
	}
}

func TestInspectCLISignatureReferencesBounds(t *testing.T) {
	data, _ := makeTestCLIImage(t)
	for _, bounds := range [][2]int{{-1, 2}, {1, 1}, {0, len(data) + 1}} {
		if _, err := InspectCLISignatureReferences(data, bounds[0], bounds[1]); err == nil {
			t.Fatalf("accepted bounds %v", bounds)
		}
	}
	if refs, err := InspectCLISignatureReferences(data, 0, len(data)); err != nil || len(refs) != 0 {
		t.Fatalf("image with no signature blobs: %#v, %v", refs, err)
	}
}
