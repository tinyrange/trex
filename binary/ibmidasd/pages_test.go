package ibmidasd

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/tinyrange/trex/binary/issi"
	starfile "github.com/tinyrange/trex/storage/star"
)

func header(address uint64) []byte {
	h := make([]byte, 64)
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint64(h[i*8:], address&0x3ff00fffffff000)
	}
	h[8] = byte(address>>58)<<2 | byte(address>>56)&3
	h[9] = byte(address >> 48)
	h[10] = byte(address >> 40)
	for _, p := range [][2]uint{{16, 34}, {24, 28}, {32, 22}, {40, 16}} {
		h[p[0]] = byte(address>>p[1])<<2 | h[p[0]]&3
	}
	h[48] = byte(address>>12)<<4 | h[48]&15
	return h
}

func TestAddressDistributionAndTaggedSectors(t *testing.T) {
	for _, address := range []uint64{0x12345678000, 0xffffffff12345000, 0x8123456789abc000, 0x70022000} {
		h := header(address)
		if got, ok := VirtualAddress(h); !ok || got != address {
			t.Fatalf("%x -> %x/%v header %x", address, got, ok, h)
		}
		// Tag maps replace bytes3..6 of a sector, while the distributed
		// address fragments and scope survive independently.
		for i := 0; i < 8; i++ {
			copy(h[i*8+3:i*8+7], []byte{0x89, 0xab, 0xcd, 0xef})
			h[i*8+7] |= 8
		}
		if got, ok := VirtualAddress(h); !ok || got != address {
			t.Fatalf("tagged %x -> %x/%v", address, got, ok)
		}
	}
	h := header(0xffffffff12345000)
	h[33] ^= 1
	if _, ok := VirtualAddress(h); ok {
		t.Fatal("mixed scopes accepted")
	}
	h = header(0xffffffff12345000)
	h[5] ^= 1
	if _, ok := VirtualAddress(h); ok {
		t.Fatal("different untagged address accepted")
	}
	h = header(0xffffffff12345000)
	h[0] |= 12
	if _, ok := VirtualAddress(h); ok {
		t.Fatal("unsupported header kind accepted")
	}
	if _, ok := VirtualAddress(make([]byte, 64)); ok {
		t.Fatal("zero header indexed")
	}
}

func TestIndexBoundedRangesDuplicatesAndBorrowedPages(t *testing.T) {
	b := make([]byte, 4*FrameBytes+17)
	for _, page := range []int{0, 2} {
		copy(b[page*FrameBytes+PageBytes+8:], header(0xffffffff70022000))
	}
	b[0] = 0x91
	b[2*FrameBytes] = 0x92
	source := &starfile.Bytes{Data: b}
	idx, err := Open(source, []Range{{2 * FrameBytes, FrameBytes}, {0, FrameBytes - 1}, {FrameBytes - 1, 1}}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if idx.Scanned != 2 || len(idx.Pages[0xffffffff70022000]) != 2 {
		t.Fatal(idx)
	}
	if a, ok, err := idx.PageAddress(2 * FrameBytes); err != nil || !ok || a != 0xffffffff70022000 {
		t.Fatalf("physical address lookup: %x, %v, %v", a, ok, err)
	}
	if _, ok, err := idx.PageAddress(FrameBytes); err != nil || ok {
		t.Fatalf("unmapped frame: %v, %v", ok, err)
	}
	for _, offset := range []int64{-1, 1, 4 * FrameBytes} {
		if _, _, err := idx.PageAddress(offset); err == nil {
			t.Fatalf("accepted incomplete or misaligned frame at %d", offset)
		}
	}
	for n, offset := range idx.Pages[0xffffffff70022000] {
		p, err := Page(source, offset)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(io.NewSectionReader(p, 0, p.Size()))
		if err != nil || got[0] != byte(0x91+n) {
			t.Fatal(got, err)
		}
	}
	b[0] = 0x93
	p, _ := Page(source, 0)
	out := make([]byte, 1)
	p.ReadAt(out, 0)
	if out[0] != 0x93 {
		t.Fatal("page was copied eagerly")
	}
	for _, ranges := range [][]Range{{{0, FrameBytes}, {FrameBytes - 1, FrameBytes}}, {{-1, 1}}, {{0, int64(len(b)) + 1}}, {{0, 4 * FrameBytes}}} {
		if _, err := Open(source, ranges, 1); err == nil {
			t.Fatal("invalid ranges/budget accepted", ranges)
		}
	}
}

func TestStampedPageIntegrityAndPartialReads(t *testing.T) {
	b := make([]byte, FrameBytes)
	for i := 0; i < PageBytes; i++ {
		b[i] = byte(i*13 + i/512)
	}
	original := bytes.Clone(b[:PageBytes])
	if err := issi.Save(b[PageBytes:], header(0xffffffff70022000), b[:PageBytes]); err != nil {
		t.Fatal(err)
	}
	if err := issi.Stamp(b[PageBytes:], b[:PageBytes], 0x1234); err != nil {
		t.Fatal(err)
	}
	source := &starfile.Bytes{Data: b}
	p, _ := Page(source, 0)
	out := make([]byte, 1500)
	if n, err := p.ReadAt(out, 500); err != nil || n != len(out) || !bytes.Equal(out, original[500:2000]) {
		t.Fatal(n, err)
	}
	if n, err := p.ReadAt(out, 4090); n != 6 || err != io.EOF || !bytes.Equal(out[:6], original[4090:]) {
		t.Fatal(n, err)
	}
	b[504] ^= 1
	if n, err := p.ReadAt(out, 0); n != 0 || err == nil {
		t.Fatal("bad control exposed", n, err)
	}
	b[504] ^= 1
	b[FrameBytes-1] ^= 1
	if _, err := p.ReadAt(out, 0); err == nil {
		t.Fatal("bad sidecar exposed")
	}
	if _, err := Page(source, 1); err == nil {
		t.Fatal("unaligned frame")
	}
	if _, err := Page(source, FrameBytes); err == nil {
		t.Fatal("truncated frame")
	}
}

func TestVirtualFilesNeverChooseVersionsOrFillHoles(t *testing.T) {
	b := make([]byte, 3*FrameBytes)
	const address = uint64(0xffffffff70022000)
	for page := 0; page < 2; page++ {
		for i := 0; i < PageBytes; i++ {
			b[page*FrameBytes+i] = byte(page + 1)
		}
		copy(b[page*FrameBytes+PageBytes+8:], header(address+uint64(page)*4096))
	}
	idx, err := Open(&starfile.Bytes{Data: b}, []Range{{0, int64(len(b))}}, 3)
	if err != nil {
		t.Fatal(err)
	}
	f, err := idx.VirtualFile(address+4090, 12)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 20)
	n, err := f.ReadAt(out, 0)
	if n != 12 || err != io.EOF || !bytes.Equal(out[:12], []byte{1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2}) {
		t.Fatal(n, err, out)
	}
	if _, err := idx.VirtualFile(address+4096, 4097); err == nil {
		t.Fatal("missing page filled")
	}
	copy(b[2*FrameBytes+PageBytes+8:], header(address))
	idx, err = Open(&starfile.Bytes{Data: b}, []Range{{0, int64(len(b))}}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idx.VirtualFile(address, 1); err == nil {
		t.Fatal("duplicate version chosen")
	}
	if _, err := idx.VirtualFile(^uint64(0)-1, 3); err == nil {
		t.Fatal("address overflow accepted")
	}
}
