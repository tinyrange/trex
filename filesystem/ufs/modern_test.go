package ufs

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

// Construct 4.4BSD fields independently of the parser. The directory bytes
// reproduce the OpenBSD installer failure: type=4/name-length=1, not length=260.
func modernFixture(order binary.ByteOrder) []byte {
	b := fixture(order)
	order.PutUint32(b[8192+1320:], 60)
	order.PutUint32(b[8192+1324:], 2)
	for _, pos := range []int{0, 12, 24} {
		n := order.Uint16(b[48*512+pos+6:])
		b[48*512+pos+6] = 4
		b[48*512+pos+7] = byte(n)
	}
	b[48*512+24+6] = 8
	file := b[32*512+3*128:]
	order.PutUint32(file[112:], 70000)
	order.PutUint32(file[116:], 80000)
	return b
}

func TestReadModernUFS1(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b := modernFixture(order)
		v, err := Open(&starfile.Bytes{Data: b}, 10, 100)
		if err != nil {
			t.Fatal(err)
		}
		if v.InodeFormat != 2 || len(v.Entries) != 2 || v.Entries[1].Path != "/file" || v.Entries[1].UID != 70000 || v.Entries[1].GID != 80000 {
			t.Fatalf("wrong modern inode metadata: %+v", v)
		}
		got, err := starfile.ReadAll(v.Entries[1].Data)
		if err != nil || string(got) != "abc" {
			t.Fatal(string(got), err)
		}
		root := auto.Open(&starfile.Bytes{Data: b}, "", auto.Options{})
		file, err := root.Resolve("file")
		if err != nil {
			t.Fatal(err)
		}
		got, err = starfile.ReadAll(file.Reader())
		if err != nil || string(got) != "abc" {
			t.Fatal(string(got), err)
		}
	}
}

func TestModernUFS4KFragments(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		old := modernFixture(order)
		b := make([]byte, 40*4096)
		copy(b[8192:8192+1376], old[8192:8192+1376])
		sb := b[8192:]
		for off, value := range map[int]uint32{16: 8, 36: 40, 48: 16384, 52: 4096, 56: 4, 116: 4096, 120: 128, 184: 128, 188: 40} {
			order.PutUint32(sb[off:], value)
		}
		for _, number := range []int{2, 3} {
			copy(b[8*4096+number*128:], old[32*512+number*128:32*512+(number+1)*128])
		}
		order.PutUint32(b[8*4096+2*128+40:], 12)
		order.PutUint32(b[8*4096+3*128+40:], 20)
		copy(b[12*4096:], old[48*512:48*512+512])
		copy(b[20*4096:], "abc")
		v, err := Open(&starfile.Bytes{Data: b}, 10, 100)
		if err != nil {
			t.Fatal(err)
		}
		if v.BlockSize != 16384 || v.FragmentSize != 4096 {
			t.Fatal(v)
		}
		got, err := starfile.ReadAll(v.Entries[1].Data)
		if err != nil || string(got) != "abc" {
			t.Fatal(string(got), err)
		}
	}
}

func TestModernSymlinksAndHardLinks(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b := modernFixture(order)
		dir := b[48*512:]
		for _, e := range []struct {
			off, length int
			ino         uint32
			kind        byte
			name        string
		}{{24, 16, 3, 8, "file"}, {40, 16, 3, 0, "alias"}, {56, 16, 4, 10, "short"}, {72, 440, 5, 10, "long"}} {
			order.PutUint32(dir[e.off:], e.ino)
			order.PutUint16(dir[e.off+4:], uint16(e.length))
			dir[e.off+6], dir[e.off+7] = e.kind, byte(len(e.name))
			copy(dir[e.off+8:], e.name+"\x00")
		}
		order.PutUint16(b[32*512+3*128+2:], 2)
		for _, ino := range []int{4, 5} {
			raw := b[32*512+ino*128:]
			order.PutUint16(raw, 0xa1ff)
			order.PutUint16(raw[2:], 1)
		}
		short := b[32*512+4*128:]
		order.PutUint64(short[8:], 4)
		copy(short[40:], "file")
		long := b[32*512+5*128:]
		// Exactly maxsymlinklen is block-backed, not inline.
		order.PutUint64(long[8:], 60)
		order.PutUint32(long[40:], 64)
		target := strings.Repeat("x", 60)
		copy(b[64*512:], target)
		v, err := Open(&starfile.Bytes{Data: b}, 10, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(v.Entries) != 5 || v.Entries[1].Data != v.Entries[2].Data {
			t.Fatal("hard-link identity lost")
		}
		for i, want := range []string{"file", target} {
			e := v.Entries[i+3]
			got, err := starfile.ReadAll(e.Data)
			if err != nil || e.Kind != "symlink" || string(got) != want {
				t.Fatal(e.Path, string(got), err)
			}
		}
	}
}

func TestModernUFSRejectsInvalidDeclarations(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b[8192+1324:], 1) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[8192+1320:], 61) },
		func(b []byte) { b[48*512+24+6] = 4 }, // directory entry claims a regular file is a directory
		func(b []byte) { b[48*512+6] = 8 },    // dot must be a directory
		func(b []byte) { b[48*512+24+7] = 255 },
		func(b []byte) { binary.LittleEndian.PutUint32(b[8192+1372:], 0x19540119) },
	} {
		b := modernFixture(binary.LittleEndian)
		mutate(b)
		if _, err := Open(&starfile.Bytes{Data: b}, 10, 100); err == nil {
			t.Fatal("accepted malformed or unsupported modern layout")
		}
	}
}

func FuzzModernUFS1(f *testing.F) {
	f.Add(modernFixture(binary.LittleEndian))
	f.Add(modernFixture(binary.BigEndian))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 256*1024 {
			return
		}
		v, err := Open(&starfile.Bytes{Data: b}, 100, 1000)
		if err == nil && len(v.Entries) > 100 {
			t.Fatal("entry bound")
		}
	})
}
