package wim

import "testing"

// Large solid offsets and split-part provenance must survive both the compact
// index and duplicate-history expansion, including after reference remapping.
func TestResourceIndexWideExtentsAndProvenance(t *testing.T) {
	a := &Archive{}
	var hash [20]byte
	want := []wimResourceLocation{
		{archive: a, blobOffset: 1<<48 + 19, blobSize: 1<<40 + 23, refCount: 0xffffffff, lookupPart: 0xffff},
		{archive: a, blobOffset: 1<<62 + 29, blobSize: 1<<61 + 31, refCount: 0x80000001, lookupPart: 0x8001},
	}
	for _, location := range want {
		a.addResourceLocation(string(hash[:]), location)
	}
	got := a.resourceLocations(string(hash[:]))
	if len(got) != len(want) {
		t.Fatalf("locations: %d", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("location %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	// Nonzero remapping must change only the backing, not adjacent refcount,
	// extent or split-part fields. The imported source may release its index.
	imported := &Archive{resourceBackings: []*wimResourceBacking{nil, nil}}
	imported.resourceBackings = append(imported.resourceBackings, a.resourceBackings...)
	imported.addIndexedLocation(hash, a.byHash[hash].remapBacking(2))
	a.byHash, a.resourceBackings = nil, nil
	selected, ok := imported.lookupResource(hash)
	if !ok || selected != want[1] {
		t.Fatalf("selected imported location: %+v, %v", selected, ok)
	}
}
