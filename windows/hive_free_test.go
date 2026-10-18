package windows

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

// Compare indexed first-fit with an independent on-disk cell walk across
// allocation, reuse, splitting, bin growth, and both hive header generations.
func TestHiveFreeIndexMatchesDiskFirstFit(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		minor := uint32(3)
		if legacy {
			minor = 1
		}
		data, err := buildRegistryHiveWithFormat(newRegistryTree("SYSTEM"), registryHiveFormat{major: 1, minor: minor})
		if err != nil {
			t.Fatal(err)
		}
		h := &mutableHive{data: data, legacyCellPrefix: legacy}
		rng := rand.New(rand.NewSource(42))
		live := map[uint32][]byte{}
		cells := []uint32{}
		for step := 0; step < 3000; step++ {
			if len(cells) > 0 && rng.Intn(3) == 0 {
				i := rng.Intn(len(cells))
				cell := cells[i]
				if err := h.freeCell(cell); err != nil {
					t.Fatal(err)
				}
				delete(live, cell)
				cells = append(cells[:i], cells[i+1:]...)
				continue
			}
			body := bytes.Repeat([]byte{byte(step)}, rng.Intn(9000)+1)
			alignment := 8
			if legacy {
				alignment = 16
			}
			needed := (len(body) + h.cellBodyOffset() + alignment - 1) &^ (alignment - 1)
			want := uint32(0)
			for bin := hiveBaseBlockSize; bin < len(h.data) && want == 0; {
				end := bin + int(binary.LittleEndian.Uint32(h.data[bin+8:]))
				for off := bin + 0x20; off < end; {
					raw := int(int32(binary.LittleEndian.Uint32(h.data[off:])))
					if raw >= needed {
						want = uint32(off - hiveBaseBlockSize)
						break
					}
					if raw < 0 {
						raw = -raw
					}
					if raw < 8 {
						t.Fatal("bad cell")
					}
					off += raw
				}
				bin = end
			}
			got, err := h.allocateCell(body)
			if err != nil {
				t.Fatal(err)
			}
			if want != 0 && got != want {
				t.Fatalf("step %d legacy %v: got %x want first fit %x", step, legacy, got, want)
			}
			live[got] = body
			cells = append(cells, got)
		}
		for cell, want := range live {
			got, err := h.cellBody(cell)
			if err != nil || len(got) < len(want) || !bytes.Equal(got[:len(want)], want) {
				t.Fatalf("live cell %x overwritten: %v", cell, err)
			}
		}
		if legacy {
			assertNT31CellLinks(t, h.data)
		}
	}
}
