package xz

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	encoder "github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

const xzFixtureBase64 = "/Td6WFoAAATm1rRGBMASDiEBFgAAAAAAAAAAAJ3BZqkBAA1oZWxsbyBmcm9tIHh6CgAAAFv5ht3mJ3rmAAEuDgCROcwftvN9AQAAAAAEWVo="

func xzFixture(t *testing.T) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(xzFixtureBase64)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAutoBeyondDefaultMaximumAndExplicitCap(t *testing.T) {
	var compressed bytes.Buffer
	w, err := (encoder.WriterConfig{DictCap: 1 << 20}).NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	source := &starfile.Bytes{Data: bytes.Repeat(compressed.Bytes(), 513)}
	result, err := auto.Identify(source, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	f := result.View.(*auto.DecodedView).Reader
	if size := f.Size(); size != 513<<20 {
		t.Fatal(size)
	}
	var got [1]byte
	if _, err := f.ReadAt(got[:], (513<<20)-1); err != nil || got[0] != 0 {
		t.Fatal(got, err)
	}
	if _, err := auto.Identify(source, auto.Options{MaxExpandedBytes: 512 << 20}); !errors.Is(err, auto.ErrLimit) {
		t.Fatal(err)
	}
}

func TestXZFileSizeSequentialAndRandomReads(t *testing.T) {
	compressed := xzFixture(t)
	file, err := Open(&starfile.Bytes{Name: "fixture.xz", Data: compressed}, defaultXZDictionaryLimit)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := file.Size(), int64(len("hello from xz\n")); got != want {
		t.Fatalf("size = %d, want %d", got, want)
	}
	first := make([]byte, 5)
	if _, err := file.ReadAt(first, 6); err != nil {
		t.Fatal(err)
	}
	if string(first) != "from " {
		t.Fatalf("middle read = %q", first)
	}
	all, err := starfile.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(all) != "hello from xz\n" {
		t.Fatalf("all = %q", all)
	}
}

func TestXZConcatenatedStreamsAndPadding(t *testing.T) {
	stream := xzFixture(t)
	data := append(append(append([]byte{}, stream...), 0, 0, 0, 0), stream...)
	file, err := Open(&starfile.Bytes{Name: "concatenated.xz", Data: data}, defaultXZDictionaryLimit)
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello from xz\nhello from xz\n" {
		t.Fatalf("decoded = %q", got)
	}
}

func TestXZRejectsCorruptIndex(t *testing.T) {
	data := xzFixture(t)
	data[len(data)-16] ^= 0x01
	if _, err := Open(&starfile.Bytes{Name: "corrupt.xz", Data: data}, defaultXZDictionaryLimit); err == nil {
		t.Fatal("corrupt XZ index was accepted")
	}
}

func TestXZARM64BranchesAndChecksum(t *testing.T) {
	le := binary.LittleEndian
	// At position 0x1000, BL +3 and ADRP -2 pages convert to absolute
	// instruction immediates 0x403 and -1 page, respectively.
	want := le.AppendUint32(le.AppendUint32(nil, 0x94000003), 0xd0fffff1)
	filtered := le.AppendUint32(le.AppendUint32(nil, 0x94000403), 0xf0fffff1)
	want, filtered = append(want, 0xef), append(filtered, 0xef)
	var data bytes.Buffer
	writer, err := (lzma.Writer2Config{DictCap: 4096}).NewWriter2(&data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(filtered); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	stream := append(append([]byte{}, xzHeaderMagic...), 0, 1)
	stream = le.AppendUint32(stream, crc32.ChecksumIEEE(stream[6:8]))
	blockHeader := []byte{3, 1, 0x0a, 4, 0, 0x10, 0, 0, 0x21, 1, 0, 0}
	stream = append(stream, le.AppendUint32(blockHeader, crc32.ChecksumIEEE(blockHeader))...)
	stream = append(stream, data.Bytes()...)
	unpadded := len(stream) - 12 + 4
	for len(stream)%4 != 0 {
		stream = append(stream, 0)
	}
	checkOffset := len(stream)
	stream = le.AppendUint32(stream, crc32.ChecksumIEEE(want))
	index := []byte{0, 1, byte(unpadded), byte(len(want))}
	stream = append(stream, le.AppendUint32(index, crc32.ChecksumIEEE(index))...)
	footer := []byte{1, 0, 0, 0, 0, 1}
	stream = le.AppendUint32(stream, crc32.ChecksumIEEE(footer))
	stream = append(append(stream, footer...), 'Y', 'Z')

	for _, corrupt := range []bool{false, true} {
		if corrupt {
			stream[checkOffset] ^= 1
		}
		file, err := Open(&starfile.Bytes{Data: stream}, defaultXZDictionaryLimit)
		if err != nil {
			t.Fatal(err)
		}
		got, err := starfile.ReadAll(file)
		if corrupt {
			if err == nil {
				t.Fatal("accepted a damaged ARM64 checksum")
			}
		} else if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("decoded %x, want %x, error %v", got, want, err)
		}
	}
}
