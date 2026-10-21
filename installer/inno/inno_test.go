package inno

import (
	"bytes"
	"compress/zlib"
	"hash/adler32"
	"hash/crc32"
	"io"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func u32(b []byte, v uint32) []byte { x := make([]byte, 4); le.PutUint32(x, v); return append(b, x...) }
func str(b []byte, s string) []byte { return append(u32(b, uint32(len(s))), []byte(s)...) }
func zipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := zlib.NewWriter(&out)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func block(t *testing.T, b []byte) []byte {
	packed := zipped(t, b)
	h := u32(nil, uint32(len(packed)))
	h = u32(h, uint32(len(b)))
	out := u32(nil, crc32.ChecksumIEEE(h))
	out = append(out, h...)
	for len(packed) > 0 {
		n := min(len(packed), 4096)
		out = u32(out, crc32.ChecksumIEEE(packed[:n]))
		out = append(out, packed[:n]...)
		packed = packed[n:]
	}
	return out
}
func fixture(t *testing.T, external bool, destination string) ([]byte, []byte) {
	primary := []byte{}
	for i := 0; i < 23; i++ {
		primary = str(primary, "")
	}
	primary = append(primary, make([]byte, 32)...)
	counts := make([]uint32, 13)
	counts[4] = 2
	counts[5] = 1
	for _, n := range counts {
		primary = u32(primary, n)
	}
	primary = append(primary, make([]byte, 54)...)
	for i := 0; i < 5; i++ {
		primary = str(primary, "")
	}
	primary = append(primary, make([]byte, 24)...)
	primary = str(primary, "")
	primary = str(primary, "")
	addFile := func(source, dest string, index, flags uint32) {
		primary = str(primary, source)
		primary = str(primary, dest)
		for i := 0; i < 4; i++ {
			primary = str(primary, "")
		}
		primary = append(primary, make([]byte, 20)...)
		primary = u32(primary, index)
		primary = u32(primary, 0)
		primary = u32(primary, 0)
		primary = u32(primary, flags)
		primary = append(primary, 0)
	}
	addFile("", destination, 0, 1<<12)
	addFile("{src}/extras/*.*", "{app}/extras/", 0xffffffff, 0)
	payload := []byte("hello native installer")
	compressed := zipped(t, payload)
	chunk := append([]byte("zlb\x1a"), compressed...)
	secondary := make([]byte, 41)
	le.PutUint32(secondary, 1)
	le.PutUint32(secondary[4:], 1)
	if external {
		le.PutUint32(secondary[8:], 12)
	}
	le.PutUint32(secondary[12:], uint32(len(payload)))
	le.PutUint32(secondary[16:], uint32(len(compressed)))
	le.PutUint32(secondary[20:], adler32.Checksum(payload))
	b := make([]byte, 192)
	copy(b, "MZ")
	copy(b[48:], "Inno")
	le.PutUint32(b[52:], 64)
	le.PutUint32(b[56:], ^uint32(64))
	copy(b[64:], "rDlPtS02\x87eVx")
	le.PutUint32(b[100:], 128)
	copy(b[128:], version3061)
	b = append(b, block(t, primary)...)
	b = append(b, block(t, secondary)...)
	if external {
		slice := append([]byte("idska32\x1a"), make([]byte, 4)...)
		slice = append(slice, chunk...)
		le.PutUint32(slice[8:], uint32(len(slice)))
		return b, slice
	}
	le.PutUint32(b[104:], uint32(len(b)))
	return append(b, chunk...), nil
}
func TestEmbeddedAndExternalSlices(t *testing.T) {
	for _, external := range []bool{false, true} {
		b, slice := fixture(t, external, "{app}/hello.txt")
		entries := []auto.Entry{{Name: "setup.exe", Kind: "file", Reader: &starfile.Bytes{Data: b}}, {Name: "extras/l\xe9eme.txt", Kind: "file", Reader: &starfile.Bytes{Data: []byte("external")}}}
		if external {
			entries = append(entries, auto.Entry{Name: "SETUP-1.BIN", Kind: "file", Reader: &starfile.Bytes{Data: slice}})
		}
		tree, err := auto.Tree(entries, auto.Options{})
		if err != nil {
			t.Fatal(err)
		}
		root := auto.FromView(tree, "", auto.Options{})
		for name, want := range map[string]string{"hello.txt": "hello native installer", "extras/léeme.txt": "external"} {
			n, err := root.Resolve("setup.exe/{app}/" + name)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(io.NewSectionReader(n.Reader(), 0, n.Reader().Size()))
			if err != nil || string(got) != want {
				t.Fatalf("%q %v", got, err)
			}
		}
	}
}
func TestHeaderChecksumsAndBounds(t *testing.T) {
	b := block(t, bytes.Repeat([]byte("native"), 1000))
	if _, _, err := headerBlock(&starfile.Bytes{Data: b}, 0, 100); err != auto.ErrLimit {
		t.Fatal(err)
	}
	for _, at := range []int{0, 4, 12, 16, len(b) - 1} {
		bad := bytes.Clone(b)
		bad[at] ^= 1
		if _, _, err := headerBlock(&starfile.Bytes{Data: bad}, 0, 1<<20); err == nil {
			t.Fatalf("accepted corrupt block at %d", at)
		}
	}
	b, _ = fixture(t, false, "{app}/../escape")
	if _, err := Open(b, &starfile.Bytes{Data: b}, auto.Options{}); err == nil {
		t.Fatal("accepted unsafe destination")
	}
}
func TestChunkChecksum(t *testing.T) {
	payload := []byte("checksummed")
	compressed := zipped(t, payload)
	source := append([]byte("zlb\x1a"), compressed...)
	// Embedded chunk starts at a nonzero base offset.
	source = append([]byte{0}, source...)
	a := &archive{source: &starfile.Bytes{Data: source}, dataOffset: 1}
	f := &file{archive: a, location: location{first: 1, last: 1, size: uint32(len(payload)), packed: uint32(len(compressed)), checksum: 1}}
	if _, err := f.decode(); err == nil {
		t.Fatal("accepted corrupt file checksum")
	}
	f.location.checksum = adler32.Checksum(payload)
	if got, err := f.decode(); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("%q %v", got, err)
	}
}
