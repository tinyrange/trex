package msdelta

import "testing"

func TestDirectoryMarkingFallsBackOnlyForUnbackedRVAs(t *testing.T) {
	for _, directory := range []int{4, 6} {
		layout := peLayout{machine: 0x14c, headerSize: 0x20, imageBaseSize: 4, imageBase: 0x10000000, imageSize: 0x400,
			sections: []peSection{{rva: 0x100, rawStart: 0x20, rawSize: 0x80, virtualSize: 0x300}},
		}
		layout.directories[directory] = peDirectory{rva: 0x200, size: 0x40}
		data, marker := make([]byte, 0x220), make([]byte, 0x220)
		// The directory lies in the section's virtual tail, not its raw backing.
		// Its in-file address instead owns the overlay, clipped at the file end.
		put32(data, 0x205, 0x10000100)
		put32(data, 0x125, 0x10000100) // not owned by a false virtual-tail mapping
		markPEDirectories(marker, layout)
		for i, got := range marker {
			want := byte(0)
			if i < 0x20 || i >= 0x200 {
				want = 3
			}
			if got != want {
				t.Fatalf("directory%d marker%#x=%d, want%d", directory, i, got, want)
			}
		}
		transformUnlistedPointersX86(data, layout, riftTable{}, 0x20000000, marker)
		if get32(data, 0x205) != 0x10000100 || get32(data, 0x125) != 0x20000100 {
			t.Fatal("overlay not protected or unrelated pointer suppressed")
		}
		// Raw-backed RVAs still take precedence over the same numeric file offset.
		layout.directories[directory] = peDirectory{rva: 0x120, size: 4}
		clear(marker)
		markPEDirectories(marker, layout)
		if marker[0x40] != 3 || marker[0x120] != 0 {
			t.Fatal("raw RVA mapping did not take precedence")
		}
		// No invented backing for an address outside both section and file.
		layout.directories[directory] = peDirectory{rva: 0x500, size: 0xffffffff}
		clear(marker)
		markPEDirectories(marker, layout)
		for _, got := range marker[0x20:] {
			if got != 0 {
				t.Fatal("out-of-file fallback was marked")
			}
		}
	}
}
