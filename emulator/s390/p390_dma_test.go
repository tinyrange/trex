package s390

import (
	"encoding/binary"
	"testing"
)

func TestP390HostStorageTransfersSetArchitecturalKeys(t *testing.T) {
	for _, compat := range []bool{false, true} {
		t.Run(map[bool]string{false: "4K", true: "2K"}[compat], func(t *testing.T) {
			p, err := NewP390WithConfig(Config{Memory: 32 << 20, CPUs: 1, S370: compat})
			if err != nil {
				t.Fatal(err)
			}
			s := p.Machine.S
			size := uint32(1) << s.KeyShift
			// A host transfer straddles two architectural key blocks, not
			// necessarily a 4K mapping-descriptor boundary.
			at := uint32(0x8000) + size - 1
			*s.key(at), *s.key(at + 1) = 0xa8, 0x58
			desc := make([]byte, 4)
			binary.LittleEndian.PutUint32(desc, 0x8000)
			if err = p.WriteAperture(0x220, desc); err != nil {
				t.Fatal(err)
			}
			offset := uint32(0x40000) + size - 1
			if err = p.WriteAperture(offset, []byte{0x37, 0x39}); err != nil {
				t.Fatal(err)
			}
			if s.Mem[at] != 0x37 || s.Mem[at+1] != 0x39 || *s.key(at) != 0xae || *s.key(at + 1) != 0x5e {
				t.Fatalf("DMA did not preserve access/fetch keys and set R/C: %x %x", *s.key(at), *s.key(at + 1))
			}
			if compat {
				c := p.Machine.CPUs[0]
				c.rrb370(at &^ 0x7ff)
				if c.PSW.CC != 3 {
					t.Fatalf("guest RRB did not observe host DMA: CC%d", c.PSW.CC)
				}
			}
			*s.key(at), *s.key(at + 1) = 0xa8, 0x58
			var got [2]byte
			if err = p.ReadAperture(offset, got[:]); err != nil {
				t.Fatal(err)
			}
			if got != [2]byte{0x37, 0x39} || *s.key(at) != 0xac || *s.key(at + 1) != 0x5c {
				t.Fatalf("host read must reference, not change: %x %x", *s.key(at), *s.key(at + 1))
			}
			// Monitor bookkeeping and explicit key-array access must not
			// manufacture storage reference/change activity.
			clear(s.Keys)
			if err = p.WriteAperture(0x180000, []byte{1}); err != nil {
				t.Fatal(err)
			}
			if err = p.WriteAperture(0x10000, []byte{0x50}); err != nil {
				t.Fatal(err)
			}
			if err = p.ReadAperture(0x10000, got[:]); err != nil {
				t.Fatal(err)
			}
			if s.Keys[0] != 0x50 || (!compat && s.Keys[1] != 0) || (compat && s.Keys[1] != 0x50) {
				t.Fatal("key/monitor access touched architectural R/C")
			}
		})
	}
}
