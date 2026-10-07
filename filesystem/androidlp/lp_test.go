package androidlp

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/tinyrange/trex/storage"
)

type testReader []byte

func (r testReader) Size() int64 { return int64(len(r)) }
func (r testReader) ReadAt(p []byte, off int64) (int, error) {
	return bytes.NewReader(r).ReadAt(p, off)
}

func signHeader(b []byte) {
	hs := le.Uint32(b[8:])
	ts := le.Uint32(b[44:])
	t := sha256.Sum256(b[hs : hs+ts])
	copy(b[48:80], t[:])
	clear(b[12:44])
	h := sha256.Sum256(b[:hs])
	copy(b[12:44], h[:])
}
func fixture(minor uint16) testReader {
	disk := make(testReader, 128*512)
	for _, off := range []int{4096, 8192} {
		g := disk[off : off+52]
		le.PutUint32(g, 0x616c4467)
		le.PutUint32(g[4:], 52)
		le.PutUint32(g[40:], 4096)
		le.PutUint32(g[44:], 2)
		le.PutUint32(g[48:], 4096)
		h := sha256.Sum256(g)
		copy(g[8:40], h[:])
	}
	hs := uint32(128)
	if minor == 2 {
		hs = 256
	}
	for _, off := range []int{12288, 16384, 20480, 24576} {
		b := disk[off : off+4096]
		le.PutUint32(b, 0x414c5030)
		le.PutUint16(b[4:], 10)
		le.PutUint16(b[6:], minor)
		le.PutUint32(b[8:], hs)
		le.PutUint32(b[44:], 52+3*24+48+64)
		start := uint32(0)
		for i, d := range [][2]uint32{{1, 52}, {3, 24}, {1, 48}, {1, 64}} {
			le.PutUint32(b[80+i*12:], start)
			le.PutUint32(b[84+i*12:], d[0])
			le.PutUint32(b[88+i*12:], d[1])
			start += d[0] * d[1]
		}
		if minor == 2 {
			le.PutUint32(b[128:], 1)
		}
		p := b[hs:]
		copy(p, "system")
		le.PutUint32(p[36:], 3)
		le.PutUint32(p[44:], 3)
		for i, sector := range []uint64{64, 0, 80} {
			e := p[52+i*24:]
			le.PutUint64(e, 1)
			le.PutUint64(e[12:], sector)
			if i == 1 {
				le.PutUint32(e[8:], 1)
			}
		}
		g := p[124:]
		copy(g, "group")
		le.PutUint64(g[40:], 1536)
		d := p[172:]
		le.PutUint64(d, 64)
		le.PutUint32(d[8:], 4096)
		le.PutUint64(d[16:], uint64(len(disk)))
		copy(d[24:], "super")
		signHeader(b)
	}
	for i := 0; i < 512; i++ {
		disk[64*512+i] = byte(i)
		disk[80*512+i] = byte(255 - i)
	}
	return disk
}

func TestVersionsSlotsAndExtentReads(t *testing.T) {
	for minor := uint16(0); minor <= 2; minor++ {
		for slot := uint32(0); slot < 2; slot++ {
			disk := fixture(minor)
			v, err := Open(disk, slot, nil)
			if err != nil {
				t.Fatal(err)
			}
			p := v.Partitions[0]
			wantName := "system_a"
			if slot == 1 {
				wantName = "system_b"
			}
			if p.Name != wantName || p.Data.Size() != 1536 || v.BackupMetadata || v.BackupGeometry || v.Major != 10 || v.Minor != minor {
				t.Fatalf("incorrect metadata: %+v", v)
			}
			want := append(append(append([]byte{}, disk[64*512:65*512]...), make([]byte, 512)...), disk[80*512:81*512]...)
			for _, span := range [][2]int{{0, 1536}, {499, 50}, {1020, 100}, {1530, 20}} {
				got := make([]byte, span[1])
				n, err := p.Data.ReadAt(got, int64(span[0]))
				end := min(len(want), span[0]+span[1])
				if n != end-span[0] || !bytes.Equal(got[:n], want[span[0]:end]) || (err == io.EOF) != (n < len(got)) {
					t.Fatalf("span %v: n=%d err=%v", span, n, err)
				}
			}
			if n, err := p.Data.ReadAt(nil, 99999); n != 0 || err != nil {
				t.Fatal(n, err)
			}
		}
	}
}

func TestBackupGeometryAndMetadata(t *testing.T) {
	disk := fixture(2)
	disk[4096+8] ^= 1
	disk[12288+12] ^= 1
	v, err := Open(disk, 0, nil)
	if err != nil || !v.BackupGeometry || !v.BackupMetadata {
		t.Fatalf("backup not selected: %+v %v", v, err)
	}
	disk[8192+8] ^= 1
	if _, err := Open(disk, 0, nil); err == nil {
		t.Fatal("accepted two bad geometry copies")
	}
	disk = fixture(2)
	disk[12288+256] ^= 1
	disk[20480+256] ^= 1
	if _, err := Open(disk, 0, nil); err == nil {
		t.Fatal("accepted two bad table checksums")
	}
}

func TestRejectInvalidSignedMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"version", func(b []byte) { le.PutUint16(b[6:], 3) }},
		{"table range", func(b []byte) { le.PutUint32(b[80:], 4096) }},
		{"table overlap", func(b []byte) { le.PutUint32(b[92:], 0) }},
		{"entry width", func(b []byte) { le.PutUint32(b[88:], 51) }},
		{"extent index", func(b []byte) { le.PutUint32(b[256+40:], 4) }},
		{"extent source", func(b []byte) { le.PutUint32(b[256+52+20:], 1) }},
		{"extent before payload", func(b []byte) { le.PutUint64(b[256+52+12:], 63) }},
		{"extent past end", func(b []byte) { le.PutUint64(b[256+52:], 1000) }},
		{"extent overflow", func(b []byte) { le.PutUint64(b[256+52:], ^uint64(0)) }},
		{"extent type", func(b []byte) { le.PutUint32(b[256+52+8:], 99) }},
		{"zero extent", func(b []byte) { le.PutUint64(b[256+76+12:], 1) }},
		{"group index", func(b []byte) { le.PutUint32(b[256+48:], 1) }},
		{"group quota", func(b []byte) { le.PutUint64(b[256+124+40:], 512) }},
		{"partition flags", func(b []byte) { le.PutUint32(b[256+36:], 16) }},
		{"name", func(b []byte) { b[256] = '/' }},
		{"name padding", func(b []byte) { b[256+35] = 'x' }},
		{"device size", func(b []byte) { le.PutUint64(b[256+172+16:], 1<<40) }},
		{"device metadata overlap", func(b []byte) { le.PutUint64(b[256+172:], 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disk := fixture(2)
			for _, off := range []int{12288, 20480} {
				b := disk[off : off+4096]
				tc.mutate(b)
				signHeader(b)
			}
			if _, err := Open(disk, 0, nil); err == nil {
				t.Fatal("accepted malformed metadata")
			}
		})
	}
	if _, err := Open(fixture(2), 2, nil); err == nil {
		t.Fatal("accepted invalid slot")
	}
	if _, err := Open(fixture(2)[:25000], 0, nil); err == nil {
		t.Fatal("accepted truncated device")
	}
}

func TestMultiplePhysicalDevices(t *testing.T) {
	disk := fixture(2)
	for _, off := range []int{12288, 20480} {
		b := disk[off : off+4096]
		le.PutUint32(b[44:], 300)
		le.PutUint32(b[120:], 2)
		copy(b[256+236:256+300], b[256+172:256+236])
		d := b[256+236:]
		clear(d[24:60])
		copy(d[24:], "other")
		le.PutUint32(b[256+52+20:], 1)
		signHeader(b)
	}
	if _, err := Open(disk, 0, nil); err == nil {
		t.Fatal("accepted missing physical device")
	}
	other := fixture(2)
	other[64*512] = 77
	v, err := Open(disk, 0, map[string]storage.Reader{"other": other})
	if err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := v.Partitions[0].Data.ReadAt(got[:], 0); err != nil || got[0] != 77 {
		t.Fatal(got, err)
	}
}
