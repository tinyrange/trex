package xfs

import (
	"bytes"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"hash/crc32"
	"math"
	"testing"
)

func btreeFixture(level int) []byte {
	b := fixture()
	f := b[9*256 : 10*256]
	f[5] = 3
	clear(f[100:])
	be.PutUint16(f[100:], uint16(level))
	be.PutUint16(f[102:], 1)
	be.PutUint64(f[104:], 1)
	capacity := (len(f) - 104) / 16
	be.PutUint64(f[104+capacity*8:], 11)
	leaf := b[11*512 : 12*512]
	be.PutUint32(leaf, 0x424d4150)
	be.PutUint16(leaf[6:], 1)
	be.PutUint64(leaf[8:], math.MaxUint64)
	be.PutUint64(leaf[16:], math.MaxUint64)
	if level == 1 {
		be.PutUint64(leaf[24:], 1<<9)
		be.PutUint64(leaf[32:], 10<<21|1)
	} else {
		be.PutUint16(leaf[4:], 1)
		be.PutUint64(leaf[24:], 1)
		be.PutUint64(leaf[24+((512-24)/16)*8:], 12)
		next := b[12*512 : 13*512]
		be.PutUint32(next, 0x424d4150)
		be.PutUint16(next[6:], 1)
		be.PutUint64(next[8:], math.MaxUint64)
		be.PutUint64(next[16:], math.MaxUint64)
		be.PutUint64(next[24:], 1<<9)
		be.PutUint64(next[32:], 10<<21|1)
	}
	return b
}
func TestBmapLevelsAndCorruption(t *testing.T) {
	for _, level := range []int{1, 2} {
		b := btreeFixture(level)
		v, err := Open(&starfile.Bytes{Data: b}, 100)
		if err != nil {
			t.Fatal(err)
		}
		got, err := starfile.ReadAll(v.Entries[1].Data)
		if err != nil || string(got[512:]) != "abc" {
			t.Fatalf("level %d data: %q %v", level, got, err)
		}
	}
	for name, mutate := range map[string]func([]byte){
		"cycle":     func(b []byte) { be.PutUint64(b[11*512+24+((512-24)/16)*8:], 11) },
		"level":     func(b []byte) { be.PutUint16(b[12*512+4:], 1) },
		"separator": func(b []byte) { be.PutUint64(b[12*512+24:], 2<<9) },
		"count":     func(b []byte) { be.PutUint32(b[9*256+76:], 2) },
		"sibling":   func(b []byte) { be.PutUint64(b[12*512+16:], 11) },
		"range":     func(b []byte) { be.PutUint64(b[12*512+32:], 32<<21|1) },
	} {
		t.Run(name, func(t *testing.T) {
			b := btreeFixture(2)
			mutate(b)
			if _, err := Open(&starfile.Bytes{Data: b}, 100); err == nil {
				t.Fatal("accepted corrupt btree")
			}
		})
	}
}
func TestRealtimeSparseAndUnwritten(t *testing.T) {
	b := fixture()
	be.PutUint64(b[16:], 8)
	be.PutUint32(b[24:], 1)
	f := b[9*256 : 10*256]
	be.PutUint16(f[90:], 1)
	be.PutUint64(f[108:], 2<<21|1)
	rt := make([]byte, 8*512)
	copy(rt[2*512:], "RT!")
	if _, err := Open(&starfile.Bytes{Data: b}, 100); err == nil {
		t.Fatal("missing realtime input accepted")
	}
	v, err := OpenRealtime(&starfile.Bytes{Data: b}, &starfile.Bytes{Data: rt}, 100)
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(v.Entries[1].Data)
	if err != nil || string(got[512:]) != "RT!" || !bytes.Equal(got[:512], make([]byte, 512)) {
		t.Fatal("wrong realtime mapping", err)
	}
	be.PutUint64(f[100:], 1<<63|1<<9)
	v, err = OpenRealtime(&starfile.Bytes{Data: b}, &starfile.Bytes{Data: rt}, 100)
	if err != nil {
		t.Fatal(err)
	}
	got, err = starfile.ReadAll(v.Entries[1].Data)
	if err != nil || !bytes.Equal(got, make([]byte, 515)) {
		t.Fatal("unwritten extent not zero", err)
	}
	be.PutUint64(f[108:], 8<<21|1)
	if _, err := OpenRealtime(&starfile.Bytes{Data: b}, &starfile.Bytes{Data: rt}, 100); err == nil {
		t.Fatal("out of range realtime extent accepted")
	}
}
func stampCRC(b []byte, offset int) {
	clear(b[offset : offset+4])
	binary.LittleEndian.PutUint32(b[offset:], crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)))
}
func v5Fixture() []byte {
	b := make([]byte, 32*1024)
	be.PutUint32(b, 0x58465342)
	be.PutUint32(b[4:], 1024)
	be.PutUint64(b[8:], 32)
	copy(b[32:], []byte("test-volume-uuid"))
	be.PutUint64(b[56:], 8)
	be.PutUint32(b[84:], 32)
	be.PutUint32(b[88:], 1)
	be.PutUint16(b[100:], 5)
	be.PutUint16(b[102:], 512)
	be.PutUint16(b[104:], 512)
	b[120], b[122], b[123], b[124] = 10, 9, 1, 5
	be.PutUint32(b[216:], 1)
	stampCRC(b[:512], 224)
	for _, id := range []int{8, 9} {
		f := b[id*512 : (id+1)*512]
		be.PutUint16(f, 0x494e)
		f[4] = 3
		be.PutUint64(f[152:], uint64(id))
		copy(f[160:], b[32:48])
	}
	root := b[8*512 : 9*512]
	be.PutUint16(root[2:], 0040755)
	root[5] = 2
	be.PutUint64(root[56:], 1024)
	be.PutUint32(root[76:], 1)
	be.PutUint64(root[184:], 10<<21|1)
	stampCRC(root, 100)
	f := b[9*512 : 10*512]
	be.PutUint16(f[2:], 0100644)
	f[5] = 3
	be.PutUint64(f[56:], 3)
	be.PutUint32(f[76:], 1)
	be.PutUint16(f[176:], 1)
	be.PutUint16(f[178:], 1)
	be.PutUint64(f[180+((512-180)/16)*8:], 11)
	stampCRC(f, 100)
	d := b[10*1024 : 11*1024]
	be.PutUint32(d, 0x58444233)
	be.PutUint64(d[8:], 20)
	copy(d[24:], b[32:48])
	be.PutUint64(d[40:], 8)
	be.PutUint64(d[64:], 9)
	d[72], d[73], d[74] = 1, 'a', 1
	be.PutUint16(d[78:], 64)
	be.PutUint16(d[80:], 0xffff)
	be.PutUint16(d[82:], 928)
	be.PutUint16(d[1006:], 80)
	be.PutUint32(d[1016:], 1)
	stampCRC(d, 4)
	leaf := b[11*1024 : 12*1024]
	be.PutUint32(leaf, 0x424d4133)
	be.PutUint16(leaf[6:], 1)
	be.PutUint64(leaf[8:], math.MaxUint64)
	be.PutUint64(leaf[16:], math.MaxUint64)
	be.PutUint64(leaf[24:], 22)
	copy(leaf[40:], b[32:48])
	be.PutUint64(leaf[56:], 9)
	be.PutUint64(leaf[80:], 12<<21|1)
	stampCRC(leaf, 64)
	copy(b[12*1024:], "v5!")
	return b
}
func TestV5Metadata(t *testing.T) {
	b := v5Fixture()
	v, err := Open(&starfile.Bytes{Data: b}, 100)
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(v.Entries[1].Data)
	if err != nil || string(got) != "v5!" {
		t.Fatal(string(got), err)
	}
	for name, mutate := range map[string]func([]byte){
		"superblock crc": func(b []byte) { b[48] ^= 1 },
		"inode crc":      func(b []byte) { b[8*512+8] ^= 1 },
		"directory crc":  func(b []byte) { b[10*1024+73] ^= 1 },
		"btree crc":      func(b []byte) { b[11*1024+80] ^= 1 },
		"wrong owner":    func(b []byte) { d := b[10*1024 : 11*1024]; be.PutUint64(d[40:], 99); stampCRC(d, 4) },
		"wrong address":  func(b []byte) { d := b[11*1024 : 12*1024]; be.PutUint64(d[24:], 99); stampCRC(d, 64) },
		"wrong uuid":     func(b []byte) { d := b[11*1024 : 12*1024]; d[40] ^= 1; stampCRC(d, 64) },
		"incompat":       func(b []byte) { be.PutUint32(b[216:], 1<<31); stampCRC(b[:512], 224) },
	} {
		t.Run(name, func(t *testing.T) {
			b := v5Fixture()
			mutate(b)
			if _, err := Open(&starfile.Bytes{Data: b}, 100); err == nil {
				t.Fatal("accepted corrupt metadata")
			}
		})
	}
}
