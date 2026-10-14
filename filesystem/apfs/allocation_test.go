package apfs

import (
	"bytes"
	"reflect"
	"testing"
)

// This fixture exercises allocation inspection, not guest mountability. The
// wrapped checkpoint contains independently checksummed ephemeral objects and
// a CIB with two stored bitmaps plus one wholly free, bitmap-less chunk.
func allocationFixture(cab bool) []byte {
	b := make([]byte, 96*4096)
	copy(b, fixture())
	put := func(pa int, p []byte) { seal(p); copy(b[pa*4096:], p) }
	nx := append([]byte(nil), b[:4096]...)
	le.PutUint32(nx[24:], 0x80000001)
	le.PutUint64(nx[40:], 96)
	le.PutUint64(nx[88:], 1027)
	le.PutUint64(nx[96:], 3)
	le.PutUint32(nx[104:], 4)
	le.PutUint32(nx[108:], 8)
	le.PutUint64(nx[112:], 16)
	le.PutUint64(nx[120:], 20)
	le.PutUint32(nx[128:], 1)
	le.PutUint32(nx[132:], 1)
	le.PutUint32(nx[136:], 3)
	le.PutUint32(nx[140:], 2)
	le.PutUint32(nx[144:], 7)
	le.PutUint32(nx[148:], 2)
	le.PutUint64(nx[152:], 1025)
	le.PutUint64(nx[168:], 1026)
	put(0, nx)
	put(16, nx)
	cp := block(0x4000000c, 19)
	le.PutUint32(cp[32:], 1)
	le.PutUint32(cp[36:], 2)
	for i, r := range []struct {
		kind   uint32
		id, pa uint64
	}{{0x80000005, 1025, 27}, {0x80000011, 1026, 20}} {
		p := cp[40+i*40:]
		le.PutUint32(p, r.kind)
		le.PutUint32(p[8:], 4096)
		le.PutUint64(p[24:], r.id)
		le.PutUint64(p[32:], r.pa)
	}
	put(19, cp)
	put(20, block(0x80000011, 1026))
	sm := block(0x80000005, 1025)
	for offset, value := range map[int]uint32{32: 4096, 36: 32, 40: 126, 44: 507, 64: 1, 80: 2560, 144: 1, 148: 16, 160: 1, 164: 16, 336: 1, 340: 2520} {
		le.PutUint32(sm[offset:], value)
	}
	for offset, value := range map[int]uint64{48: 96, 56: 3, 72: 50, 152: 4, 168: 32, 176: 28, 2560: 29} {
		le.PutUint64(sm[offset:], value)
	}
	if cab {
		le.PutUint32(sm[68:], 1)
		le.PutUint64(sm[2560:], 28)
	}
	put(27, sm)
	cib := block(0x40000007, 29)
	le.PutUint32(cib[36:], 3)
	for i, r := range []struct{ start, free, bitmap uint64 }{{0, 2, 30}, {32, 16, 31}, {64, 32, 0}} {
		p := cib[40+i*32:]
		le.PutUint64(p, 2)
		le.PutUint64(p[8:], r.start)
		le.PutUint32(p[16:], 32)
		le.PutUint32(p[20:], uint32(r.free))
		le.PutUint64(p[24:], r.bitmap)
	}
	put(29, cib)
	le.PutUint32(b[30*4096:], 0xffff3fff)
	le.PutUint32(b[31*4096:], 0x0000ffff)
	if cab {
		p := block(0x40000006, 28)
		le.PutUint32(p[36:], 1)
		le.PutUint64(p[40:], 29)
		put(28, p)
	}
	return b
}

func TestAllocationCheckpointWrapAndChunkMaps(t *testing.T) {
	for _, cab := range []bool{false, true} {
		c, err := Open(bytes.NewReader(allocationFixture(cab)))
		if err != nil {
			t.Fatal(err)
		}
		a, err := c.Allocation()
		if err != nil {
			t.Fatal(err)
		}
		if a.Transaction != 2 || a.Superblock != 16 || a.SpaceManager != 27 || a.FreeBlocks != 50 || len(a.Mappings) != 2 || len(a.Chunks) != 3 || !reflect.DeepEqual(a.Free, []BlockRange{{14, 2}, {48, 48}}) {
			t.Fatalf("allocation %+v", a)
		}
		if a.Chunks[2].Bitmap != nil || a.Chunks[2].Free != 32 {
			t.Fatal("wholly free chunk interpretation")
		}
	}
}

func TestAllocationRejectsUnsafeMetadata(t *testing.T) {
	editBlock := func(b []byte, pa int, edit func([]byte)) { p := b[pa*4096 : (pa+1)*4096]; edit(p); seal(p) }
	for name, edit := range map[string]func([]byte){
		"ephemeral-checksum":                 func(b []byte) { b[27*4096+90] ^= 1 },
		"ephemeral-wrong-id":                 func(b []byte) { editBlock(b, 27, func(p []byte) { le.PutUint64(p[8:], 1030) }) },
		"checkpoint-map-outside-active-ring": func(b []byte) { editBlock(b, 19, func(p []byte) { le.PutUint64(p[72:], 26) }) },
		"checkpoint-overlapping-mappings":    func(b []byte) { editBlock(b, 19, func(p []byte) { le.PutUint64(p[112:], 27) }) },
		"checkpoint-incomplete-mapping":      func(b []byte) { editBlock(b, 19, func(p []byte) { le.PutUint32(p[36:], 1) }) },
		"checkpoint-ring-next":               func(b []byte) { editBlock(b, 16, func(p []byte) { le.PutUint32(p[128:], 2) }) },
		"spaceman-address-overflow":          func(b []byte) { editBlock(b, 27, func(p []byte) { le.PutUint32(p[80:], 0xfffffff8) }) },
		"cib-checksum":                       func(b []byte) { b[29*4096+90] ^= 1 },
		"chunk-overlap":                      func(b []byte) { editBlock(b, 29, func(p []byte) { le.PutUint64(p[80:], 31) }) },
		"bitmap-count-mismatch":              func(b []byte) { b[30*4096] ^= 1 },
		"null-bitmap-not-free":               func(b []byte) { editBlock(b, 29, func(p []byte) { le.PutUint32(p[124:], 31) }) },
		"container-free-count-mismatch":      func(b []byte) { editBlock(b, 27, func(p []byte) { le.PutUint64(p[72:], 51) }) },
		"metadata-marked-free": func(b []byte) {
			b[30*4096] &^= 1
			editBlock(b, 29, func(p []byte) { le.PutUint32(p[60:], 3) })
			editBlock(b, 27, func(p []byte) { le.PutUint64(p[72:], 51) })
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := allocationFixture(false)
			edit(b)
			c, err := Open(bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Allocation(); err == nil {
				t.Fatal("accepted invalid allocation map")
			}
		})
	}
}
