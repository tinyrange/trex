package ntfs

import "testing"

func TestAttributeListWindowsZeroCapacity(t *testing.T) {
	entry := ntfsNamedAttributeListEntry(ntfsAttrData, "stream", 9, 40)
	for _, padding := range []int{1, 25, 64, 4096} {
		data := append(append([]byte(nil), entry...), make([]byte, padding)...)
		got, err := parseNTFSReadAttributeList(data)
		if err != nil || len(got) != 1 || got[0].record != 40 || got[0].name != "stream" {
			t.Fatalf("padding %d: entries=%v err=%v", padding, got, err)
		}
		data[len(data)-1] = 1
		if _, err := parseNTFSReadAttributeList(data); err == nil {
			t.Fatalf("accepted nonzero truncated trailing entry with padding %d", padding)
		}
	}
	if _, err := parseNTFSReadAttributeList(make([]byte, 64)); err == nil {
		t.Fatal("accepted all-zero list without a valid entry")
	}
	truncated := append(append([]byte(nil), entry...), entry[:25]...)
	if _, err := parseNTFSReadAttributeList(truncated); err == nil {
		t.Fatal("accepted truncated actual entry")
	}
}
