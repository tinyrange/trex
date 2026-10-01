package openbsd

import (
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
)

func checksum(raw []byte, order binary.ByteOrder) {
	order.PutUint16(raw[136:], 0)
	var sum uint16
	for i := 0; i < 148+int(order.Uint16(raw[138:]))*16; i += 2 {
		sum ^= order.Uint16(raw[i:])
	}
	order.PutUint16(raw[136:], sum)
}

// A complete v1 label with an FFS partition, empty b, and overlapping raw c.
// Fields and addresses follow the disklabel declarations, independently of Open.
func fixture(order binary.ByteOrder, sectorSize uint32, labelOffset int) []byte {
	b := make([]byte, 128*int(sectorSize))
	h := b[labelOffset:]
	order.PutUint32(h, 0x82564557)
	order.PutUint32(h[132:], 0x82564557)
	order.PutUint16(h[114:], 1)
	order.PutUint16(h[138:], 3)
	order.PutUint32(h[40:], sectorSize)
	order.PutUint32(h[60:], 128)
	order.PutUint32(h[80:], 8)
	order.PutUint32(h[84:], 128)
	copy(h[64:72], "labeluid")
	copy(h[8:24], "test disk")
	order.PutUint32(h[148:], 16)
	order.PutUint32(h[152:], 8)
	h[160], h[161] = 7, 0x13 // FFS, 16 KiB block / 4 KiB fragment
	order.PutUint32(h[180:], 128)
	copy(b[8*int(sectorSize):], "payload")
	checksum(h, order)
	return b
}

func TestReadLabelSectorGeometryAndViews(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, sectorSize := range []uint32{512, 4096} {
			b := fixture(order, sectorSize, int(sectorSize))
			l, err := Open(&starfile.Bytes{Data: b}, int64(sectorSize))
			if err != nil {
				t.Fatal(err)
			}
			if l.SectorSize != sectorSize || l.Sectors != 128 || l.BoundStart != 8 || l.BoundEnd != 128 || string(l.UID[:]) != "labeluid" {
				t.Fatalf("wrong label: %+v", l)
			}
			p := l.Partitions[0]
			if p.Name != "a" || p.Start != 8 || p.Sectors != 16 || p.Type != 7 || p.FragmentSize != 4096 || p.BlockSize != 16384 || p.Data.Size() != 16*int64(sectorSize) {
				t.Fatalf("wrong partition: %+v", p)
			}
			var got [7]byte
			if _, err := p.Data.ReadAt(got[:], 0); err != nil || string(got[:]) != "payload" {
				t.Fatal(string(got[:]), err)
			}
			if _, err := p.Data.ReadAt(got[:], p.Data.Size()); err != io.EOF {
				t.Fatal("partition read escaped range", err)
			}
			if l.Partitions[1].Data != nil || l.Partitions[2].Data.Size() != int64(len(b)) {
				t.Fatal("empty/raw slots lost")
			}
		}
	}
}

func TestReadLabelAtOuterPartitionOffset(t *testing.T) {
	b := fixture(binary.LittleEndian, 512, 8192+512)
	if _, err := Open(&starfile.Bytes{Data: b}, 512); err == nil {
		t.Fatal("guessed label position")
	}
	l, err := Open(&starfile.Bytes{Data: b}, 8192+512)
	if err != nil {
		t.Fatal(err)
	}
	var got [7]byte
	if _, err := l.Partitions[0].Data.ReadAt(got[:], 0); err != nil || string(got[:]) != "payload" {
		t.Fatal("partition offsets became relative to label", string(got[:]), err)
	}
}

func TestEmptyLabelTable(t *testing.T) {
	b := fixture(binary.LittleEndian, 512, 512)
	h := b[512:]
	binary.LittleEndian.PutUint16(h[138:], 0)
	checksum(h, binary.LittleEndian)
	l, err := Open(&starfile.Bytes{Data: b}, 512)
	if err != nil || len(l.Partitions) != 0 {
		t.Fatal(l, err)
	}
}

func TestReadLabel48BitAddresses(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b := fixture(order, 512, 512)
		h := b[512:]
		// Sparse caller-owned storage tests high address bits without a host disk.
		order.PutUint16(h[112:], 1) // total sectors: 2^32 + 128
		order.PutUint16(h[78:], 1)  // bound end
		order.PutUint16(h[156:], 1) // a offset high
		order.PutUint16(h[190:], 1) // c size high
		checksum(h, order)
		start := (int64(1)<<32 | 8) * 512
		size := (int64(1)<<32 | 128) * 512
		source := filesystem.NewGeneratedImage("high-sector fixture", size, []filesystem.ExtentSpec{
			{Start: 512, Size: 512, Data: append([]byte(nil), h[:512]...)},
			{Start: start, Size: 7, Data: []byte("payload")},
		})
		l, err := Open(source, 512)
		if err != nil {
			t.Fatal(err)
		}
		if l.Partitions[0].Start != 1<<32|8 || l.Partitions[2].Sectors != 1<<32|128 {
			t.Fatal("high bits lost")
		}
		var got [7]byte
		if _, err := l.Partitions[0].Data.ReadAt(got[:], 0); err != nil || string(got[:]) != "payload" {
			t.Fatal(string(got[:]), err)
		}
	}
}

func TestLabelValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
		want   string
	}{
		{"magic", func(h []byte) { h[0] = 0 }, "magic"},
		{"second magic", func(h []byte) { h[132] = 0 }, "magic"},
		{"version", func(h []byte) { binary.LittleEndian.PutUint16(h[114:], 2) }, "version"},
		{"checksum", func(h []byte) { h[64] ^= 1 }, "checksum"},
		{"count", func(h []byte) { binary.LittleEndian.PutUint16(h[138:], 53) }, "count"},
		{"sector", func(h []byte) { binary.LittleEndian.PutUint32(h[40:], 513); checksum(h, binary.LittleEndian) }, "sector"},
		{"bounds", func(h []byte) { binary.LittleEndian.PutUint32(h[84:], 129); checksum(h, binary.LittleEndian) }, "geometry"},
		{"label bounds", func(h []byte) {
			binary.LittleEndian.PutUint32(h[60:], 1)
			binary.LittleEndian.PutUint32(h[80:], 0)
			binary.LittleEndian.PutUint32(h[84:], 1)
			checksum(h, binary.LittleEndian)
		}, "label outside"},
		{"partition", func(h []byte) { binary.LittleEndian.PutUint32(h[148:], 128); checksum(h, binary.LittleEndian) }, "outside disk"},
		{"overflow", func(h []byte) {
			binary.LittleEndian.PutUint32(h[40:], 65536)
			binary.LittleEndian.PutUint16(h[112:], 65535)
			checksum(h, binary.LittleEndian)
		}, "geometry"},
		{"FFS encoding", func(h []byte) { h[161] = 0x10; checksum(h, binary.LittleEndian) }, "FFS geometry"},
		{"small fragment", func(h []byte) {
			binary.LittleEndian.PutUint32(h[40:], 4096)
			h[161] = 0x14
			checksum(h, binary.LittleEndian)
		}, "fragment smaller"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := fixture(binary.LittleEndian, 512, 512)
			tc.mutate(b[512:])
			_, err := Open(&starfile.Bytes{Data: b}, 512)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatal(err)
			}
		})
	}
	b := fixture(binary.LittleEndian, 512, 512)
	for _, length := range []int{0, 512 + 147, 512 + 148 + 47, len(b) - 1} {
		if _, err := Open(&starfile.Bytes{Data: b[:length]}, 512); err == nil {
			t.Fatal("accepted truncated disk", length)
		}
	}
	if _, err := Open(nil, 512); err == nil {
		t.Fatal("accepted nil")
	}
	if _, err := Open(&starfile.Bytes{Data: b}, -1); err == nil {
		t.Fatal("accepted negative offset")
	}
}

func TestAutoLabelAndRawSlot(t *testing.T) {
	b := fixture(binary.LittleEndian, 512, 512)
	root := auto.Open(&starfile.Bytes{Data: b}, "disk", auto.Options{})
	meta, err := root.Metadata()
	if err != nil || meta.Format != "openbsd_label" {
		t.Fatal(meta, err)
	}
	children, err := root.Children()
	if err != nil || len(children) != 3 {
		t.Fatal(children, err)
	}
	raw, err := root.Resolve("c")
	if err != nil {
		t.Fatal(err)
	}
	children, err = raw.Children()
	if err != nil || len(children) != 0 {
		t.Fatal("raw slot recursed", children, err)
	}
	b[512+64] ^= 1
	if _, err := auto.Open(&starfile.Bytes{Data: b}, "", auto.Options{}).Children(); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatal("bad label silently ignored", err)
	}
}

func ffsFixture() []byte {
	b := fixture(binary.LittleEndian, 512, 512)
	sb := b[8192:]
	for off, value := range map[int]uint32{16: 32, 36: 128, 44: 1, 48: 4096, 52: 512, 56: 8, 116: 1024, 120: 32, 184: 32, 188: 128, 1324: 2, 1372: 0x11954} {
		binary.LittleEndian.PutUint32(sb[off:], value)
	}
	ino := b[32*512+2*128:]
	binary.LittleEndian.PutUint16(ino, 0x41ed)
	binary.LittleEndian.PutUint16(ino[2:], 2)
	binary.LittleEndian.PutUint64(ino[8:], 512)
	binary.LittleEndian.PutUint32(ino[40:], 48)
	dir := b[48*512:]
	for _, e := range []struct {
		off, length int
		name        string
	}{{0, 12, "."}, {12, 500, ".."}} {
		binary.LittleEndian.PutUint32(dir[e.off:], 2)
		binary.LittleEndian.PutUint16(dir[e.off+4:], uint16(e.length))
		dir[e.off+6], dir[e.off+7] = 4, byte(len(e.name))
		copy(dir[e.off+8:], e.name)
	}
	return b
}

func TestAutoStandaloneFFSWithParentDisklabel(t *testing.T) {
	b := ffsFixture()
	h := b[512:]
	// The supplied file is a volume view, while the embedded label still
	// describes a larger parent disk, exactly as in install79.img partition4.
	binary.LittleEndian.PutUint32(h[60:], 136)
	binary.LittleEndian.PutUint32(h[84:], 136)
	binary.LittleEndian.PutUint32(h[148:], 128)
	binary.LittleEndian.PutUint32(h[180:], 136)
	checksum(h, binary.LittleEndian)
	root := auto.Open(&starfile.Bytes{Data: b}, "volume", auto.Options{})
	meta, err := root.Metadata()
	if err != nil || meta.Format != "ufs" {
		t.Fatal(meta, err)
	}
	if _, err := root.Children(); err != nil {
		t.Fatal(err)
	}
}

func TestAutoWholeDiskWithZeroStartFFS(t *testing.T) {
	b := ffsFixture()
	h := b[512:]
	binary.LittleEndian.PutUint32(h[148:], 128)
	binary.LittleEndian.PutUint32(h[152:], 0)
	h[161] = 4 // 4096-byte blocks, 512-byte fragments
	checksum(h, binary.LittleEndian)
	root := auto.Open(&starfile.Bytes{Data: b}, "disk", auto.Options{})
	meta, err := root.Metadata()
	if err != nil || meta.Format != "openbsd_label" {
		t.Fatal(meta, err)
	}
	a, err := root.Resolve("a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Children(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Resolve("a"); err == nil {
		t.Fatal("filesystem slot reopened its own label")
	}
}

func FuzzLabel(f *testing.F) {
	f.Add(fixture(binary.LittleEndian, 512, 512))
	f.Add(fixture(binary.BigEndian, 4096, 512))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		l, err := Open(&starfile.Bytes{Data: b}, 512)
		if err == nil && len(l.Partitions) > 52 {
			t.Fatal("partition bound")
		}
	})
}
