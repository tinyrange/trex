package msdelta

import "testing"

func TestUnlistedI386PointersBoundsAndMarkers(t *testing.T) {
	layout := peLayout{machine: 0x14c, imageBaseSize: 4, imageBase: 0x10000000, imageSize: 0x1000, headerSize: 16}
	rift := riftTable{entries: []riftEntry{{source: 0, target: 16}}}
	for _, test := range []struct {
		name  string
		off   int
		value uint32
		mark  byte
		maps  bool
	}{
		{"before headers end", 12, 0x10000100, 0, false},
		{"headers end", 16, 0x10000100, 0, true},
		{"unaligned", 17, 0x10000100, 0, true},
		{"last visited", 91, 0x10000100, 0, true},
		{"exclusive final four bytes", 92, 0x10000100, 0, false},
		{"image base excluded", 32, 0x10000000, 0, false},
		{"first image byte", 32, 0x10000001, 0, true},
		{"last image byte", 32, 0x10000fff, 0, true},
		{"image end excluded", 32, 0x10001000, 0, false},
		{"noncode marker allowed", 32, 0x10000100, 1, true},
		{"directory marker excluded", 32, 0x10000100, 2, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, marker := make([]byte, 96), make([]byte, 96)
			put32(data, test.off, test.value)
			marker[test.off+3] = test.mark // Any of the four bytes can exclude it.
			transformRelocations(data, layout, rift, 0x20000000, marker)
			want := test.value
			if test.maps {
				want = 0x20000000 + test.value - 0x10000000 + 16
			}
			if got := get32(data, test.off); got != want {
				t.Fatalf("got %#x, want %#x", got, want)
			}
			if test.maps {
				for _, mark := range marker[test.off : test.off+4] {
					if mark&1 == 0 {
						t.Fatal("candidate not marked")
					}
				}
			}
		})
	}
}

func TestUnlistedI386PointersSkipClaimedCandidateWidth(t *testing.T) {
	data, marker := make([]byte, 32), make([]byte, 32)
	layout := peLayout{machine: 0x14c, imageBaseSize: 4, imageBase: 0x10000000, imageSize: 0x2000000, headerSize: 16}
	put32(data, 16, 0x10001000)
	data[20] = 0x10 // The overlapping value at17 would also qualify.
	marker[16] = 2
	want := get32(data, 17)
	transformRelocations(data, layout, riftTable{}, 0x20000000, marker)
	if get32(data, 17) != want || marker[17] != 0 {
		t.Fatal("marked candidate did not consume four bytes")
	}
}

func TestUnlistedI386PointersDoNotReplaceExplicitRelocationsOrAMD64(t *testing.T) {
	for _, machine := range []uint16{0x14c, 0x8664} {
		data, marker := make([]byte, 256), make([]byte, 256)
		layout := peLayout{machine: machine, imageBaseSize: 4, imageBase: 0x10000000, imageSize: 0x2000, headerSize: 16,
			sections: []peSection{{rva: 0x1000, rawStart: 16, rawSize: 240, virtualSize: 240}},
		}
		if machine == 0x14c {
			layout.directories[5] = peDirectory{rva: 0x1080, size: 8}
		}
		put32(data, 32, 0x10000100)
		transformRelocations(data, layout, riftTable{}, 0x20000000, marker)
		if get32(data, 32) != 0x10000100 {
			t.Fatal("fallback scan applied to explicit relocation/AMD64 path")
		}
	}
}
