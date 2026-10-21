package erofs

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"sync"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func checksum(b []byte) {
	clear(b[1028:1032])
	block := 1 << b[1036]
	end := block
	if block <= 1024 {
		end += 1024
	}
	le.PutUint32(b[1028:], ^crc32.Checksum(b[1024:end], crc32.MakeTable(crc32.Castagnoli)))
}
func dirData(ids []uint64, names []string, kinds []byte) []byte {
	b := make([]byte, len(names)*12)
	for i, name := range names {
		le.PutUint64(b[i*12:], ids[i])
		le.PutUint16(b[i*12+8:], uint16(len(b)))
		b[i*12+10] = kinds[i]
		b = append(b, name...)
	}
	return b
}
func baseFixture(extended bool) []byte {
	b := make([]byte, 128*4096)
	le.PutUint32(b[1024:], 0xe0f5e1e2)
	le.PutUint32(b[1032:], 7)
	b[1036] = 12
	le.PutUint16(b[1038:], 64)
	le.PutUint64(b[1040:], 3)
	le.PutUint64(b[1048:], 1230768000)
	le.PutUint32(b[1056:], 123)
	le.PutUint32(b[1060:], 128)
	le.PutUint32(b[1104:], 3)
	le.PutUint16(b[1108:], 1)
	le.PutUint16(b[1152:], 14)
	le.PutUint16(b[1156:], 16)
	d := dirData([]uint64{64, 64, 96, 112, 96}, []string{".", "..", "copy", "link", "payload"}, []byte{2, 2, 1, 7, 1})
	root := b[2048:]
	le.PutUint16(root, 4)
	le.PutUint16(root[4:], 0040755)
	le.PutUint16(root[6:], 2)
	le.PutUint32(root[8:], uint32(len(d)))
	copy(root[32:], d)
	p := b[3072:]
	le.PutUint16(p[4:], 0100644)
	le.PutUint16(p[2:], 2)
	if extended {
		le.PutUint16(p, 1)
		le.PutUint32(p[24:], 42)
		le.PutUint32(p[28:], 43)
		le.PutUint64(p[32:], 999)
		le.PutUint32(p[40:], 20)
		le.PutUint32(p[44:], 2)
	} else {
		le.PutUint16(p[6:], 2)
		le.PutUint16(p[24:], 42)
		le.PutUint16(p[26:], 43)
		le.PutUint32(p[12:], 5)
	}
	link := b[3584:]
	le.PutUint16(link, 4)
	le.PutUint16(link[4:], 0120777)
	le.PutUint16(link[6:], 1)
	le.PutUint32(link[8:], 7)
	copy(link[32:], "payload")
	return b
}
func fileSize(b []byte, size int) {
	if le.Uint16(b[3072:])&1 != 0 {
		le.PutUint64(b[3080:], uint64(size))
	} else {
		le.PutUint32(b[3080:], uint32(size))
	}
}
func flatFixture(extended, inline bool) ([]byte, []byte) {
	b := baseFixture(extended)
	p := b[3072:]
	le.PutUint32(p[16:], 8)
	want := make([]byte, 4096+9)
	for i := range want {
		want[i] = byte(i*17 + i/91)
	}
	if inline {
		le.PutUint16(p, le.Uint16(p)|4)
		tail := 3072 + 32 + 16
		if extended {
			tail += 32
		}
		copy(b[8*4096:], want[:4096])
		copy(b[tail:], want[4096:])
	} else {
		copy(b[8*4096:], want)
	}
	fileSize(b, len(want))
	checksum(b)
	return b, want
}
func appendLength(b []byte, n int) []byte {
	for n >= 255 {
		b = append(b, 255)
		n -= 255
	}
	return append(b, byte(n))
}

// Build an independently specified raw LZ4 sequence: literal prefix, a repeated
// 32-byte history match, then five final literals. With a long literal prefix
// this requires two physical blocks and exercises big-cluster block counts.
func encoded(size int, big bool) ([]byte, []byte) {
	literal := 32
	if big {
		literal = 6000
	}
	prefix := make([]byte, literal)
	for i := range prefix {
		prefix[i] = byte(1 + i%251)
	}
	want := append([]byte(nil), prefix...)
	for len(want) < size-5 {
		want = append(want, want[len(want)-32])
	}
	want = append(want, []byte("final")...)
	b := appendLength([]byte{0xff}, literal-15)
	b = append(b, prefix...)
	b = append(b, 32, 0)
	b = appendLength(b, size-literal-5-4-15)
	b = append(b, 0x50)
	b = append(b, []byte("final")...)
	return b, want
}
func putBits(b []byte, bit, width uint64, value uint64) {
	for i := uint64(0); i < width; i++ {
		if value&(1<<i) != 0 {
			b[(bit+i)/8] |= 1 << ((bit + i) % 8)
		}
	}
}

func compressedFixture(layout uint16, two, big bool, count int, separate bool) ([]byte, []byte) {
	b := baseFixture(false)
	p := b[3072:]
	le.PutUint16(p, layout<<1)
	le.PutUint16(p[2:], 0)
	size := count*4096 - 17
	fileSize(b, size)
	mapStart := 3104
	indexes := mapStart + 8
	advise := uint16(0)
	if two {
		advise |= 1
	}
	if big {
		advise |= 6
	}
	le.PutUint16(b[mapStart+4:], advise)
	var want []byte
	physicalBlocks := uint64(1)
	if big {
		physicalBlocks = 2
	}
	if separate {
		for i := 0; i < count; i++ {
			length := 4096
			if i == count-1 {
				length -= 17
			}
			data, payload := encoded(length, false)
			start := (8 + i) * 4096
			copy(b[start+4096-len(data):start+4096], data)
			want = append(want, payload...)
		}
	} else {
		data, payload := encoded(size, big)
		want = payload
		start := 8 * 4096
		end := start + int(physicalBlocks)*4096
		copy(b[end-len(data):end], data)
	}
	le.PutUint32(p[16:], uint32(physicalBlocks))
	if layout == 1 {
		for i := 0; i < count; i++ {
			row := b[indexes+8+i*8:]
			if i == 0 || separate {
				le.PutUint16(row, 1)
				le.PutUint32(row[4:], uint32(8+i))
			} else {
				le.PutUint16(row, 2)
				delta := uint16(i)
				if big && i == 1 {
					delta = 2048 | uint16(physicalBlocks)
				}
				le.PutUint16(row[4:], delta)
				le.PutUint16(row[6:], uint16(count-i))
			}
		}
	} else {
		// Our fixed inode places six 4-byte indexes before a 32-byte aligned
		// body of 16-entry packs. Remaining entries use two-entry 4-byte packs.
		for first := 0; first < count; {
			stride, entries, pos := 4, 2, indexes+first*4
			if two && first >= 6 && first < 6+(count-6)/16*16 {
				stride = 2
				entries = 16
				pos = indexes + 24 + (first-6)*2
			} else if two && first >= 6 {
				body := (count - 6) / 16 * 16
				pos = indexes + 24 + body*2 + (first-6-body)*4
			}
			pack := b[pos : pos+stride*entries]
			width := uint64((stride*entries - 4) * 8 / entries)
			for j := 0; j < entries && first+j < count; j++ {
				i := first + j
				kind, low := uint64(2), uint64(i)
				if i == 0 || separate {
					kind = 1
					low = 0
				} else if big && i == 1 {
					low = 2048 | physicalBlocks
				} else if j == entries-1 {
					low = uint64(count - i)
				}
				putBits(pack, uint64(j)*width, width, low|kind<<12)
			}
			base := uint32(8)
			if !big {
				base--
			}
			if separate {
				base += uint32(first)
			}
			le.PutUint32(pack[stride*entries-4:], base)
			first += entries
		}
	}
	checksum(b)
	return b, want
}
func payload(t *testing.T, b []byte) *auto.Node {
	t.Helper()
	root := auto.Open(&starfile.Bytes{Data: b}, "image", auto.Options{})
	m, err := root.Metadata()
	if err != nil || m.Format != "erofs" {
		t.Fatalf("detect: %+v %v", m, err)
	}
	n, err := root.Resolve("payload")
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func checkReads(t *testing.T, r *auto.Node, want []byte) {
	t.Helper()
	data, err := io.ReadAll(io.NewSectionReader(r.Reader(), 0, r.Reader().Size()))
	if err != nil || !bytes.Equal(data, want) {
		t.Fatalf("full payload: len=%d expected=%d err=%v", len(data), len(want), err)
	}
	for _, span := range [][2]int{{0, 23}, {4090, 30}, {len(want) - 9, 20}, {7, 13}, {min(16*4096+13, len(want)-9), 19}} {
		got := make([]byte, span[1])
		n, err := r.Reader().ReadAt(got, int64(span[0]))
		end := min(len(want), span[0]+span[1])
		if n != end-span[0] || !bytes.Equal(got[:n], want[span[0]:end]) || (err == io.EOF) != (n < len(got)) {
			t.Fatalf("span %v: n=%d err=%v", span, n, err)
		}
	}
	if _, err := r.Reader().ReadAt(make([]byte, 1), -1); err == nil {
		t.Fatal("accepted negative offset")
	}
	if n, err := r.Reader().ReadAt(nil, int64(len(want)+1)); n != 0 || err != nil {
		t.Fatal(n, err)
	}
}
func TestFlatInlineAndExtendedInodes(t *testing.T) {
	for _, extended := range []bool{false, true} {
		for _, inline := range []bool{false, true} {
			t.Run(fmt.Sprintf("extended%t/inline%t", extended, inline), func(t *testing.T) {
				b, want := flatFixture(extended, inline)
				n := payload(t, b)
				checkReads(t, n, want)
				if n.Summary().Attributes["uid"] != uint32(42) || n.Summary().Attributes["links"] != uint32(2) {
					t.Fatal(n.Summary())
				}
				mtime, nsec := uint64(1230768005), uint32(123)
				if extended {
					mtime, nsec = 999, 20
				}
				if n.Summary().Attributes["mtime"] != mtime || n.Summary().Attributes["mtime_nsec"] != nsec {
					t.Fatal(n.Summary())
				}
				root := auto.Open(&starfile.Bytes{Data: b}, "", auto.Options{})
				link, err := root.Resolve("link")
				if err != nil || link.Summary().Attributes["target"] != "payload" || link.Reader() != nil {
					t.Fatal(link, err)
				}
				copy, err := root.Resolve("copy")
				if err != nil {
					t.Fatal(err)
				}
				checkReads(t, copy, want)
			})
		}
	}
}
func TestCompressedIndexesAndBigClusters(t *testing.T) {
	for _, layout := range []uint16{1, 3} {
		for _, two := range []bool{false, true} {
			if layout == 1 && two {
				continue
			}
			for _, big := range []bool{false, true} {
				t.Run(fmt.Sprintf("layout%d/two%t/big%t", layout, two, big), func(t *testing.T) {
					b, want := compressedFixture(layout, two, big, 38, false)
					checkReads(t, payload(t, b), want)
				})
			}
		}
	}
	for _, layout := range []uint16{1, 3} {
		for _, two := range []bool{false, true} {
			if layout == 1 && two {
				continue
			}
			t.Run(fmt.Sprintf("separate/layout%d/two%t", layout, two), func(t *testing.T) {
				b, want := compressedFixture(layout, two, false, 38, true)
				checkReads(t, payload(t, b), want)
			})
		}
	}
}
func TestMalformedFilesystemAndDirectories(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]byte)
	}{
		{"bad checksum", func(b []byte) { b[1030] ^= 1 }},
		{"size", func(b []byte) { le.PutUint32(b[1060:], 999999); checksum(b) }},
		{"unsupported feature", func(b []byte) { le.PutUint32(b[1104:], 128); checksum(b) }},
		{"invalid nanoseconds", func(b []byte) { le.PutUint32(b[1056:], 1000000000); checksum(b) }},
		{"unsupported inode layout", func(b []byte) { le.PutUint16(b[3072:], 8); checksum(b) }},
		{"root mode", func(b []byte) { le.PutUint16(b[2052:], 0100644); checksum(b) }},
		{"inline extent", func(b []byte) { le.PutUint32(b[2056:], 4095); checksum(b) }},
		{"directory name offset", func(b []byte) { le.PutUint16(b[2088:], 1); checksum(b) }},
		{"directory name", func(b []byte) { b[2148] = '/'; checksum(b) }},
		{"directory type", func(b []byte) { b[2080+2*12+10] = 2; checksum(b) }},
		{"inode pointer", func(b []byte) { le.PutUint64(b[2080+2*12:], ^uint64(0)); checksum(b) }},
		{"flat extent", func(b []byte) { le.PutUint32(b[3088:], 128); checksum(b) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := flatFixture(false, false)
			tc.change(b)
			root := auto.Open(&starfile.Bytes{Data: b}, "", auto.Options{})
			_, err := root.Children()
			if err == nil {
				t.Fatal("accepted malformed filesystem")
			}
		})
	}
	b, _ := flatFixture(false, false)
	if _, err := Open(b[:1027], &starfile.Bytes{Data: b}, auto.Options{}); err != auto.ErrNoMatch {
		t.Fatal(err)
	}
	if _, err := Open(b, nil, auto.Options{}); err == nil {
		t.Fatal("accepted missing source")
	}
	if _, err := auto.Open(&starfile.Bytes{Data: b[:2000]}, "", auto.Options{}).Children(); err == nil {
		t.Fatal("accepted truncated image")
	}
	if _, err := auto.Open(&starfile.Bytes{Data: b}, "", auto.Options{MaxEntries: 1}).Children(); err == nil {
		t.Fatal("entry limit ignored")
	}
}

func TestSmallFilesystemBlocksAndLegacyLZ4(t *testing.T) {
	for _, bits := range []byte{9, 10, 11} {
		b, want := flatFixture(false, true)
		b[1036] = bits
		copy(b[8*(1<<bits):], want[:4096])
		checksum(b)
		checkReads(t, payload(t, b), want)
	}
	b, want := compressedFixture(3, true, false, 38, false)
	le.PutUint32(b[1104:], 1) // original LZ4 scheme, no configuration table
	checksum(b)
	checkReads(t, payload(t, b), want)
}
func TestCorruptCompressedDataAndMaps(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]byte)
	}{
		{"match distance", func(b []byte) { clear(b[8*4096 : 9*4096]); copy(b[8*4096:], []byte{0x10, 'a', 0, 0}) }},
		{"all zero block", func(b []byte) { clear(b[8*4096 : 9*4096]) }},
		{"invalid back reference", func(b []byte) { le.PutUint16(b[3132:], 0); checksum(b) }},
		{"physical extent", func(b []byte) { le.PutUint32(b[3124:], 9999); checksum(b) }},
		{"algorithm", func(b []byte) { b[3110] = 3; checksum(b) }},
		{"extent record mode", func(b []byte) { le.PutUint16(b[3108:], 1); checksum(b) }},
		{"unsupported full cluster flags", func(b []byte) { le.PutUint16(b[3120:], 0x4001); checksum(b) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := compressedFixture(1, false, false, 4, false)
			tc.change(b)
			n := payload(t, b)
			if _, err := io.ReadAll(io.NewSectionReader(n.Reader(), 0, n.Reader().Size())); err == nil {
				t.Fatal("accepted bad compressed data")
			}
		})
	}
	for _, b := range [][]byte{{0xff}, {0x10, 'a', 0, 0}, {0x10, 'a', 2, 0}, {0x20, 'a'}, {0x1f, 'a', 1, 0, 255}} {
		if _, err := lz4Prefix(b, 100); err == nil {
			t.Fatalf("accepted malformed LZ4 %x", b)
		}
	}
}
func TestConcurrentRandomReads(t *testing.T) {
	b, want := compressedFixture(3, true, true, 38, false)
	n := payload(t, b)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			off := i*4096 + 7
			got := make([]byte, 80)
			_, err := n.Reader().ReadAt(got, int64(off))
			if err != nil || !bytes.Equal(got, want[off:off+80]) {
				t.Errorf("concurrent read %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestClusterOffsetsAndInterlacedPlainData(t *testing.T) {
	for _, interlaced := range []bool{false, true} {
		t.Run(fmt.Sprintf("interlaced%t", interlaced), func(t *testing.T) {
			b := baseFixture(false)
			le.PutUint16(b[3072:], 2) // full compression indexes
			le.PutUint16(b[3074:], 0)
			fileSize(b, 3*4096-17)
			if interlaced {
				le.PutUint16(b[3108:], 16)
			}
			starts := []int{0, 4096 + 137, 8192 + 70, 3*4096 - 17}
			var want []byte
			for i := 0; i < 3; i++ {
				row := b[3120+i*8:]
				le.PutUint16(row, 1)
				le.PutUint16(row[2:], uint16(starts[i]%4096))
				le.PutUint32(row[4:], uint32(8+i))
				length := starts[i+1] - starts[i]
				data, expected := encoded(length, false)
				page := b[(8+i)*4096 : (9+i)*4096]
				if i == 1 {
					le.PutUint16(row, 0) // plain extent straddles logical clusters
					for j := range expected {
						expected[j] = byte(j*19 + j/7)
					}
					if interlaced {
						for j, v := range expected {
							page[(starts[i]%4096+j)%4096] = v
						}
					} else {
						copy(page, expected)
					}
				} else {
					copy(page[4096-len(data):], data)
				}
				want = append(want, expected...)
			}
			checksum(b)
			n := payload(t, b)
			checkReads(t, n, want)
			for _, off := range []int{4096, starts[1] - 1, starts[1], 8192, starts[2] - 1, starts[2]} {
				got := make([]byte, 200)
				if _, err := n.Reader().ReadAt(got, int64(off)); err != nil || !bytes.Equal(got, want[off:off+len(got)]) {
					t.Fatalf("boundary %d: %v", off, err)
				}
			}
		})
	}
}

func TestMultiblockDirectoryAndCycles(t *testing.T) {
	b, _ := flatFixture(false, false)
	le.PutUint16(b[2048:], 0)
	le.PutUint32(b[2064:], 80)
	first := dirData([]uint64{64, 64, 96}, []string{".", "..", "copy"}, []byte{2, 2, 1})
	last := dirData([]uint64{112, 96}, []string{"link", "payload"}, []byte{7, 1})
	copy(b[80*4096:], first)
	copy(b[81*4096:], last)
	le.PutUint32(b[2056:], uint32(4096+len(last)))
	checksum(b)
	root := auto.Open(&starfile.Bytes{Data: b}, "", auto.Options{})
	children, err := root.Children()
	if err != nil || len(children) != 3 || children[0].Name() != "copy" || children[1].Name() != "link" || children[2].Name() != "payload" {
		t.Fatal(children, err)
	}
	// A non-dot directory entry referring to an ancestor is never traversed.
	le.PutUint64(b[80*4096+24:], 64)
	b[80*4096+24+10] = 2
	root = auto.Open(&starfile.Bytes{Data: b}, "", auto.Options{})
	child, err := root.Resolve("copy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := child.Children(); err == nil {
		t.Fatal("followed ancestor directory cycle")
	}
	root = auto.Open(&starfile.Bytes{Data: b}, "", auto.Options{MaxDepth: 1})
	child, err = root.Resolve("copy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := child.Children(); err == nil {
		t.Fatal("depth limit ignored")
	}
}
