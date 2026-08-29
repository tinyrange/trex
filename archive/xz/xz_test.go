package xz

import (
	"encoding/base64"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
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
