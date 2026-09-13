package fat

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

type countedFile struct {
	*starfile.Bytes
	read int
}

func (f *countedFile) ReadAt(p []byte, off int64) (int, error) {
	n, e := f.Bytes.ReadAt(p, off)
	f.read += n
	return n, e
}
func rangeFixture(kind int) (*fatFile, *countedFile) {
	source := &countedFile{Bytes: &starfile.Bytes{Data: make([]byte, 4096)}}
	for j := range source.Data {
		source.Data[j] = byte(j / 512)
	}
	fat := make([]byte, 32)
	set := func(cluster, value uint32) {
		switch kind {
		case 12:
			off := cluster + cluster/2
			word := binary.LittleEndian.Uint16(fat[off:])
			if cluster%2 == 0 {
				word = (word & 0xf000) | uint16(value&0xfff)
			} else {
				word = (word & 0xf) | uint16(value&0xfff)<<4
			}
			binary.LittleEndian.PutUint16(fat[off:], word)
		case 16:
			binary.LittleEndian.PutUint16(fat[cluster*2:], uint16(value))
		case 32:
			binary.LittleEndian.PutUint32(fat[cluster*4:], value)
		}
	}
	set(2, 5)
	set(5, 3)
	set(3, 0xffffffff)
	i := &fatImage{file: source, bytesPerSector: 512, sectorsPerCluster: 1, totalSectors: 8, fatType: kind, fat: fat}
	return &fatFile{image: i, entry: fatDirEntry{cluster: 2, size: 1536}}, source
}
func TestBoundedFragmentedReads(t *testing.T) {
	for _, kind := range []int{12, 16, 32} {
		f, s := rangeFixture(kind)
		// A prefix read must not allocate or read the declared multi-GiB file.
		f.entry.size = 4 << 30
		p := make([]byte, 128)
		if n, e := f.ReadAt(p, 0); n != 128 || e != nil || s.read != 128 || len(f.clusters) != 1 {
			t.Fatal(kind, n, e, s.read)
		}
		f.entry.size = 1536
		s.read = 0
		p = make([]byte, 40)
		if n, e := f.ReadAt(p, 500); n != 40 || e != nil || s.read != 40 || !bytes.Equal(p[:12], make([]byte, 12)) || !bytes.Equal(p[12:], bytes.Repeat([]byte{3}, 28)) {
			t.Fatal(kind, n, e, s.read, p)
		}
		s.read = 0
		if n, e := f.ReadAt(p[:3], 1024); n != 3 || e != nil || s.read != 3 || p[0] != 1 {
			t.Fatal(kind, n, e, s.read, p)
		}
		if n, e := f.ReadAt(p, 1530); n != 6 || e != io.EOF {
			t.Fatal(n, e)
		}
		if n, e := f.ReadAt(nil, 1536); n != 0 || e != nil {
			t.Fatal(n, e)
		}
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, e := f.ReadAt(make([]byte, 8), 512)
				if e != nil {
					t.Error(e)
				}
			}()
		}
		wg.Wait()
	}
}
func TestRejectBadFileChains(t *testing.T) {
	for _, next := range []uint16{0, 1, 2, 0xfff7, 0xffff, 100} {
		f, _ := rangeFixture(16)
		binary.LittleEndian.PutUint16(f.image.fat[4:], next)
		if _, err := f.ReadAt(make([]byte, 1), 512); err == nil {
			t.Fatal("accepted chain", next)
		}
	}
	f, s := rangeFixture(16)
	s.Data = s.Data[:4]
	if _, err := f.ReadAt(make([]byte, 8), 0); err == nil {
		t.Fatal("accepted truncated data")
	}
}
