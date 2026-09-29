package squashfs

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/tinyrange/trex/auto"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
	encoder "github.com/ulikunitz/xz"
)

func encode(t *testing.T, b []byte, codec uint16) []byte {
	t.Helper()
	var out bytes.Buffer
	var w io.WriteCloser
	var err error
	switch codec {
	case 1:
		w = zlib.NewWriter(&out)
	case 4:
		w, err = (encoder.WriterConfig{DictCap: 1 << 20}).NewWriter(&out)
	case 6:
		w, err = zstd.NewWriter(&out, zstd.WithEncoderConcurrency(1))
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func fixture(t *testing.T, codec uint16, fragment, sparse, extended bool) ([]byte, []byte) {
	t.Helper()
	image := make([]byte, 96)
	appendData := func(b []byte) uint64 { off := uint64(len(image)); image = append(image, b...); return off }
	meta := func(b []byte) uint64 {
		packed := encode(t, b, codec)
		word := uint16(len(packed))
		if len(packed) >= len(b) {
			packed = b
			word = uint16(len(b)) | 0x8000
		}
		h := make([]byte, 2)
		le.PutUint16(h, word)
		return appendData(append(h, packed...))
	}
	want := append(bytes.Repeat([]byte("x"), 4096), []byte("end")...)
	if sparse {
		clear(want[:4096])
	}
	data := encode(t, want[:4096], codec)
	start := uint64(len(image))
	sizeWord := uint32(len(data))
	if sparse {
		sizeWord = 0
	} else {
		appendData(data)
	}
	tail := []byte("end")
	if fragment {
		tail = []byte("__end__")
	}
	tailStart := appendData(tail)
	fragID := uint32(0xffffffff)
	if fragment {
		fragID = 0
	}
	base := func(kind uint16, number uint32) []byte {
		b := make([]byte, 16)
		le.PutUint16(b, kind)
		le.PutUint16(b[2:], 0755)
		le.PutUint32(b[12:], number)
		return b
	}
	root := base(1, 1)
	dir := make([]byte, 16)
	le.PutUint32(dir[4:], 2)
	le.PutUint16(dir[8:], 26)
	root = append(root, dir...)
	regKind := uint16(2)
	if extended {
		regKind = 9
	}
	file := base(regKind, 2)
	if extended {
		b := make([]byte, 40)
		le.PutUint64(b, start)
		le.PutUint64(b[8:], uint64(len(want)))
		le.PutUint32(b[24:], 1)
		le.PutUint32(b[28:], fragID)
		if fragment {
			le.PutUint32(b[32:], 2)
		}
		le.PutUint32(b[36:], 0xffffffff)
		file = append(file, b...)
	} else {
		b := make([]byte, 16)
		le.PutUint32(b, uint32(start))
		le.PutUint32(b[4:], fragID)
		if fragment {
			le.PutUint32(b[8:], 2)
		}
		le.PutUint32(b[12:], uint32(len(want)))
		file = append(file, b...)
	}
	words := []uint32{sizeWord}
	if !fragment {
		words = append(words, (1<<24)|3)
	}
	for _, v := range words {
		b := make([]byte, 4)
		le.PutUint32(b, v)
		file = append(file, b...)
	}
	allInodes := append(root, file...)
	// Deliberately split the file inode across metadata blocks.
	inodeTable := meta(allInodes[:45])
	meta(allInodes[45:])
	dirBytes := make([]byte, 23)
	le.PutUint32(dirBytes[8:], 2)
	le.PutUint16(dirBytes[12:], 32)
	le.PutUint16(dirBytes[16:], 2)
	le.PutUint16(dirBytes[18:], 2)
	copy(dirBytes[20:], "bin")
	directoryTable := meta(dirBytes)
	fragmentTable := uint64(0xffffffffffffffff)
	if fragment {
		b := make([]byte, 16)
		le.PutUint64(b, tailStart)
		le.PutUint32(b[8:], (1<<24)|uint32(len(tail)))
		off := meta(b)
		ptr := make([]byte, 8)
		le.PutUint64(ptr, off)
		fragmentTable = appendData(ptr)
	}
	idOffset := meta([]byte{42, 0, 0, 0})
	ptr := make([]byte, 8)
	le.PutUint64(ptr, idOffset)
	idTable := appendData(ptr)
	copy(image, "hsqs")
	le.PutUint32(image[4:], 2)
	le.PutUint32(image[12:], 4096)
	if fragment {
		le.PutUint32(image[16:], 1)
	}
	le.PutUint16(image[20:], codec)
	le.PutUint16(image[22:], 12)
	le.PutUint16(image[26:], 1)
	le.PutUint16(image[28:], 4)
	le.PutUint64(image[40:], uint64(len(image)))
	le.PutUint64(image[48:], idTable)
	le.PutUint64(image[64:], inodeTable)
	le.PutUint64(image[72:], directoryTable)
	le.PutUint64(image[80:], fragmentTable)
	return image, want
}
func TestFilesystemBlocksFragmentsAndSparse(t *testing.T) {
	for _, codec := range []uint16{1, 4, 6} {
		for _, fragment := range []bool{false, true} {
			for _, sparse := range []bool{false, true} {
				t.Run(fmt.Sprintf("codec%d/fragment%t/sparse%t", codec, fragment, sparse), func(t *testing.T) {
					b, want := fixture(t, codec, fragment, sparse, fragment)
					node, err := auto.Open(&starfile.Bytes{Data: b}, "test.squashfs", auto.Options{}).Resolve("bin")
					if err != nil {
						t.Fatal(err)
					}
					r := node.Reader()
					got, err := io.ReadAll(io.NewSectionReader(r, 0, r.Size()))
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("payload: %v", err)
					}
					out := make([]byte, 12)
					n, err := r.ReadAt(out, 4093)
					if n != 6 || err != io.EOF || !bytes.Equal(out[:n], want[4093:]) {
						t.Fatalf("cross-boundary EOF: %d %v", n, err)
					}
					if _, err = r.ReadAt(out, -1); err == nil {
						t.Fatal("negative offset accepted")
					}
					if got := node.Summary().Attributes["uid"]; got != uint32(42) {
						t.Fatalf("uid: %v", got)
					}
				})
			}
		}
	}
}
func TestMalformedMetadataAndExtents(t *testing.T) {
	for _, change := range []func([]byte){
		func(b []byte) { le.PutUint64(b[40:], uint64(len(b)+1)) },
		func(b []byte) { le.PutUint64(b[32:], 0xffff) },
		func(b []byte) { le.PutUint64(b[48:], uint64(len(b)-1)) },
		func(b []byte) { b[le.Uint64(b[64:])] = 0; b[le.Uint64(b[64:])+1] = 0 },
	} {
		b, _ := fixture(t, 1, false, false, false)
		change(b)
		v, err := Open(b, &starfile.Bytes{Data: b}, auto.Options{})
		if err == nil {
			_, err = v.Entries()
		}
		if err == nil {
			t.Fatal("accepted corrupt filesystem")
		}
	}
	s := &image{codec: 1, cache: bytecache.New(8192)}
	if _, err := s.decode(encode(t, bytes.Repeat([]byte{1}, 8193), 1), false, 8192); err != auto.ErrLimit {
		t.Fatalf("expansion bound: %v", err)
	}
	b, _ := fixture(t, 1, true, false, true)
	v, err := Open(b, &starfile.Bytes{Data: b}, auto.Options{MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	es, err := v.Entries()
	if err != nil {
		t.Fatal(err)
	}
	f := es[0].Reader.(*file)
	f.fragmentOffset = uint32(4096)
	if _, err = f.ReadAt(make([]byte, 3), 4096); err == nil {
		t.Fatal("accepted fragment overflow")
	}
}
