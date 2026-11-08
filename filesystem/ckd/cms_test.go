package ckd

import (
	"bytes"
	"strings"
	"testing"
)

const (
	cmsBlock     = 512
	cmsPerTrack  = 5
	cmsHeads     = 2
	cmsCylinders = 30
	cmsTrackSize = 4096
)

// cmsFixture builds an EDF minidisk at cylinder 1 of a P370 image. Blocks are
// allocated sequentially from block 6; block 3 is the label, block 4 the
// directory's only data block and block 5 its pointer block.
type cmsFixture struct {
	blocks map[uint32][]byte
	next   uint32
	fsts   [][]byte
}

func newCMSFixture() *cmsFixture { return &cmsFixture{blocks: map[uint32][]byte{}, next: 6} }

func (c *cmsFixture) alloc(b []byte) uint32 {
	n := c.next
	c.next++
	block := make([]byte, cmsBlock)
	copy(block, b)
	c.blocks[n] = block
	return n
}

func fst(name, typ string, recfm byte, lrecl, origin, blocks, records uint32, levels, ptr byte) []byte {
	b := make([]byte, 64)
	copy(b, eb(name, 8))
	copy(b[8:], eb(typ, 8))
	copy(b[24:], eb("A1", 2))
	b[30] = recfm
	be.PutUint32(b[32:], lrecl)
	be.PutUint32(b[40:], origin)
	be.PutUint32(b[44:], blocks)
	be.PutUint32(b[48:], records)
	b[52], b[53] = levels, ptr
	copy(b[54:], []byte{0x04, 0x02, 0x02, 0x17, 0x38, 0x26})
	return b
}

// variable packs records into a 2-byte-length-prefixed stream and returns
// level-0 pointer entries with EDF displacement semantics.
func (c *cmsFixture) variable(records [][]byte) [][3]uint32 {
	var stream []byte
	var starts []int
	for _, r := range records {
		starts = append(starts, len(stream))
		stream = append(stream, byte(len(r)>>8), byte(len(r)))
		stream = append(stream, r...)
	}
	var out [][3]uint32
	begun := 0
	for off := 0; off < len(stream); off += cmsBlock {
		end := min(off+cmsBlock, len(stream))
		disp := uint32(0xffffffff)
		for begun < len(starts) && starts[begun] < end {
			if disp == 0xffffffff {
				disp = uint32(starts[begun] - off)
			}
			begun++
		}
		if disp == 0xffffffff && end == len(stream) {
			disp = uint32(end - off) // final block: end of data
		}
		chunk := stream[off:end]
		block := uint32(0)
		if !bytes.Equal(chunk, make([]byte, len(chunk))) || end == len(stream) {
			block = c.alloc(chunk)
		}
		out = append(out, [3]uint32{block, uint32(begun), disp})
	}
	return out
}

func pointers(entries [][3]uint32) []byte {
	b := make([]byte, 0, 12*len(entries))
	for _, e := range entries {
		b = be.AppendUint32(b, e[0])
		b = be.AppendUint32(b, e[1])
		b = be.AppendUint32(b, e[2])
	}
	return b
}

func (c *cmsFixture) image(t testing.TB) []byte {
	t.Helper()
	label := make([]byte, cmsBlock)
	copy(label, cmsLabelMagic)
	copy(label[4:], eb("TST191", 6))
	for i, v := range []uint32{cmsBlock, 4, cmsCylinders - 1, cmsCylinders - 1, (cmsCylinders - 1) * cmsHeads * cmsPerTrack, c.next, 64, cmsBlock / 64} {
		be.PutUint32(label[12+4*i:], v)
	}
	copy(label[44:], []byte{0x03, 0x06, 0x17, 0x15, 0x04, 0x53})
	c.blocks[3] = label
	fsts := append([][]byte{
		fst("", "DIRECTOR", 0xc6, 64, 5, 1, uint32(len(c.fsts)+2), 1, 4),
		fst("", "ALLOCMAP", 0xc6, cmsBlock, 0, 0, 0, 0, 4),
	}, c.fsts...)
	copy(fsts[0], []byte{0, 0, 0, 1, 0, 0, 0, 0})
	copy(fsts[1], []byte{0, 0, 0, 2, 0, 0, 0, 0})
	dir := bytes.Join(fsts, nil)
	if len(dir) > cmsBlock {
		t.Fatal("fixture directory exceeds one block")
	}
	c.blocks[4] = append(dir, make([]byte, cmsBlock-len(dir))...)
	c.blocks[5] = append(be.AppendUint32(nil, 4), make([]byte, cmsBlock-4)...)
	tracks := make([][]Record, cmsCylinders*cmsHeads)
	for t := range tracks {
		tracks[t] = []Record{r(0, nil, make([]byte, 8))}
	}
	for t := 0; t < (cmsCylinders-1)*cmsHeads; t++ {
		for k := 0; k < cmsPerTrack; k++ {
			n := uint32(t*cmsPerTrack + k + 1)
			data := c.blocks[n]
			if data == nil {
				data = make([]byte, cmsBlock)
			}
			tracks[cmsHeads+t] = append(tracks[cmsHeads+t], r(byte(k+1), nil, data))
		}
	}
	return cmsP370(tracks)
}

// cmsP370 is image() with a track size large enough for 512-byte blocks.
func cmsP370(tracks [][]Record) []byte {
	b := make([]byte, 512+cmsTrackSize*len(tracks))
	copy(b, "CKD_P370")
	le.PutUint32(b[8:], cmsHeads)
	le.PutUint32(b[12:], cmsTrackSize)
	b[16] = 0x90
	for t, rs := range tracks {
		p := 512 + t*cmsTrackSize
		be.PutUint16(b[p+1:], uint16(t/cmsHeads))
		be.PutUint16(b[p+3:], uint16(t%cmsHeads))
		p += 5
		for _, rec := range rs {
			be.PutUint16(b[p:], uint16(t/cmsHeads))
			be.PutUint16(b[p+2:], uint16(t%cmsHeads))
			b[p+4] = rec.Number
			be.PutUint16(b[p+6:], uint16(len(rec.Data)))
			copy(b[p+8:], rec.Data)
			p += 8 + len(rec.Data)
		}
		copy(b[p:], bytes.Repeat([]byte{255}, 8))
	}
	return b
}

type cmsCase struct {
	fixture *cmsFixture
	want    map[string][]byte
}

func buildCMS(t testing.TB) cmsCase {
	c := newCMSFixture()
	want := map[string][]byte{}
	// Fixed, one level, with an unallocated (zero) middle block.
	fixed := bytes.Repeat([]byte("F"), 3*cmsBlock)
	clear(fixed[cmsBlock : 2*cmsBlock])
	b1, b3 := c.alloc(fixed[:cmsBlock]), c.alloc(fixed[2*cmsBlock:])
	ptr := c.alloc(be.AppendUint32(be.AppendUint32(be.AppendUint32(nil, b1), 0), b3))
	c.fsts = append(c.fsts, fst("FIXED", "DATA", 0xc6, 128, ptr, 2, 12, 1, 4))
	want["FIXED DATA"] = fixed
	// Fixed, single block, no pointer tree.
	c.fsts = append(c.fsts, fst("SMALL", "DATA", 0xc6, 10, c.alloc([]byte("0123456789abcdefghij")), 1, 2, 0, 4))
	want["SMALL DATA"] = []byte("0123456789abcdefghij")
	// Fixed, two levels, whose first level-1 subtree is entirely unallocated.
	level1 := c.alloc(be.AppendUint32(be.AppendUint32(nil, c.alloc([]byte("tail"))), 0))
	top := c.alloc(be.AppendUint32(be.AppendUint32(nil, 0), level1))
	sparseBlocks := cmsBlock/4 + 2
	c.fsts = append(c.fsts, fst("SPARSE", "DCSS", 0xc6, cmsBlock, top, 1, uint32(sparseBlocks), 2, 4))
	sparse := make([]byte, sparseBlocks*cmsBlock)
	copy(sparse[(cmsBlock/4)*cmsBlock:], "tail")
	want["SPARSE DCSS"] = sparse
	// Variable, one level: records spanning blocks, a block where no record
	// begins, an all-zero unallocated block inside a long record, and a final
	// block holding only the end of a record.
	records := [][]byte{[]byte("short"), bytes.Repeat([]byte("L"), 700), make([]byte, 1100), []byte("x"), append(bytes.Repeat([]byte("T"), 400), 1)}
	var stream []byte
	for _, rec := range records {
		stream = append(append(stream, byte(len(rec)>>8), byte(len(rec))), rec...)
	}
	entries := c.variable(records)
	c.fsts = append(c.fsts, fst("SPAN", "EXEC", 0xe5, 1100, c.alloc(pointers(entries)), uint32(len(entries)), uint32(len(records)), 1, 12))
	want["SPAN EXEC"] = stream
	// Variable, two levels: the first level-1 block is full (pointer blocks
	// are dense) and the second subtree is pure continuation.
	perBlock := cmsBlock / 12
	long := [][]byte{[]byte("a"), bytes.Repeat([]byte("B"), perBlock*cmsBlock+100)}
	var longStream []byte
	for _, rec := range long {
		longStream = append(append(longStream, byte(len(rec)>>8), byte(len(rec))), rec...)
	}
	le0 := c.variable(long)
	sub1, sub2 := c.alloc(pointers(le0[:perBlock])), c.alloc(pointers(le0[perBlock:]))
	upper := c.alloc(pointers([][3]uint32{{sub1, le0[perBlock-1][1], 0}, {sub2, le0[len(le0)-1][1], 0xffffffff}}))
	c.fsts = append(c.fsts, fst("DEEP", "MODULE", 0xe5, 65535, upper, uint32(len(le0)), 2, 2, 12))
	want["DEEP MODULE"] = longStream
	return cmsCase{c, want}
}

func TestCMSReadsEDFMinidisk(t *testing.T) {
	cc := buildCMS(t)
	d := openTest(t, cc.fixture.image(t))
	m, err := OpenCMS(d, 1, cmsCylinders-1)
	if err != nil {
		t.Fatal(err)
	}
	if m.Label.ID != "TST191" || m.BlocksPerTrack != cmsPerTrack || m.Label.Created != "030617150453" {
		t.Fatalf("label %+v per track %d", m.Label, m.BlocksPerTrack)
	}
	files, err := m.Files(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2+len(cc.want) || files[0].Type != "DIRECTOR" || files[1].Type != "ALLOCMAP" || files[2].Date != "040202173826" {
		t.Fatalf("directory %+v", files)
	}
	for _, f := range files[2:] {
		got, err := m.Content(f, 1<<20)
		if err != nil {
			t.Fatalf("%s %s: %v", f.Name, f.Type, err)
		}
		if want := cc.want[f.Name+" "+f.Type]; !bytes.Equal(got, want) {
			t.Fatalf("%s %s: %d bytes, want %d", f.Name, f.Type, len(got), len(want))
		}
	}
	if _, err := m.Content(files[2], 100); err == nil {
		t.Fatal("ignored max bytes")
	}
	if _, err := OpenCMS(d, 1, 10); err == nil || !strings.Contains(err.Error(), "extent") {
		t.Fatal("label larger than directory extent accepted", err)
	}
	if _, err := OpenCMS(d, 2, 0); err == nil {
		t.Fatal("opened a cylinder without a label")
	}
}

func TestCMSRejectsInconsistentPointers(t *testing.T) {
	find := func(c *cmsFixture, name string) []byte {
		for _, f := range c.fsts {
			if Identifier(f[:8]) == name {
				return f
			}
		}
		t.Fatal("missing", name)
		return nil
	}
	cases := map[string]struct {
		file   string
		mutate func(c *cmsFixture, f []byte)
	}{
		"record-count": {"SPAN", func(c *cmsFixture, f []byte) { be.PutUint32(f[48:], 6) }},
		"lrecl":        {"SPAN", func(c *cmsFixture, f []byte) { be.PutUint32(f[32:], 600) }},
		"last-record": {"SPAN", func(c *cmsFixture, f []byte) {
			p := c.blocks[be.Uint32(f[40:])]
			be.PutUint32(p[4:], be.Uint32(p[4:])+1)
		}},
		"displacement": {"SPAN", func(c *cmsFixture, f []byte) {
			p := c.blocks[be.Uint32(f[40:])]
			be.PutUint32(p[12+8:], be.Uint32(p[12+8:])+1)
		}},
		"upper-displacement": {"DEEP", func(c *cmsFixture, f []byte) {
			p := c.blocks[be.Uint32(f[40:])]
			be.PutUint32(p[12+8:], 0)
		}},
		"outside": {"SMALL", func(c *cmsFixture, f []byte) { be.PutUint32(f[40:], 1<<20) }},
		"short-tree": {"FIXED", func(c *cmsFixture, f []byte) {
			be.PutUint32(f[48:], 12+cmsBlock) // more records than the tree's single pointer block can address
			f[52] = 0
		}},
		"recfm": {"SMALL", func(c *cmsFixture, f []byte) { f[30] = 0xc4 }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cc := buildCMS(t)
			f := find(cc.fixture, tc.file)
			tc.mutate(cc.fixture, f)
			m, err := OpenCMS(openTest(t, cc.fixture.image(t)), 1, 0)
			if err != nil {
				t.Fatal(err)
			}
			files, err := m.Files(100)
			if err != nil {
				return // rejected while parsing the directory
			}
			for _, x := range files {
				if x.Name == tc.file {
					if _, err := m.Content(x, 1<<20); err == nil {
						t.Fatal("accepted inconsistent file")
					}
					return
				}
			}
			t.Fatal("file vanished")
		})
	}
	cc := buildCMS(t)
	m, err := OpenCMS(openTest(t, cc.fixture.image(t)), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.FilesAt(6, 100); err == nil {
		t.Fatal("accepted a non-directory block as a directory")
	}
}

// FuzzCMSPointers replaces a variable file's pointer block and FST tail with
// arbitrary bytes; decoding must fail or succeed without panicking.
func FuzzCMSPointers(f *testing.F) {
	f.Add(make([]byte, cmsBlock), make([]byte, 32))
	f.Fuzz(func(t *testing.T, block, tail []byte) {
		cc := buildCMS(t)
		for _, x := range cc.fixture.fsts {
			if Identifier(x[:8]) == "SPAN" || Identifier(x[:8]) == "DEEP" {
				copy(cc.fixture.blocks[be.Uint32(x[40:])], block)
				copy(x[32:], tail)
			}
		}
		m, err := OpenCMS(openTest(t, cc.fixture.image(t)), 1, 0)
		if err != nil {
			return
		}
		files, err := m.Files(100)
		if err != nil {
			return
		}
		for _, x := range files {
			_, _ = m.Content(x, 1<<20)
		}
	})
}
