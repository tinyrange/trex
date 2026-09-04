package szdd

import (
	"bytes"
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func szddTestFile(decodedSize int, payload []byte) *starfile.Bytes {
	header := make([]byte, 14)
	copy(header, szddSignature)
	header[8] = 'A'
	binary.LittleEndian.PutUint32(header[10:14], uint32(decodedSize))
	return &starfile.Bytes{Name: "fixture.ex_", Data: append(header, payload...)}
}

func TestSZDDDecodesLiteralsAndMatches(t *testing.T) {
	// Eight literals place "TinyRang" at 0xff0, then a match copies "Tiny".
	file := szddTestFile(12, []byte{0xff, 'T', 'i', 'n', 'y', 'R', 'a', 'n', 'g', 0x00, 0xf0, 0xf1})
	got, err := decodeSZDD(file, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte("TinyRangTiny"); !bytes.Equal(got, want) {
		t.Fatalf("decoded = %q, want %q", got, want)
	}
}

func TestSZDDAcceptsFilenameReplacementCharacter(t *testing.T) {
	file := szddTestFile(1, []byte{1, 'x'})
	file.Data[9] = 'f'
	got, err := decodeSZDD(file, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("x")) {
		t.Fatalf("decoded = %q, want x", got)
	}
}

func TestSZDDRejectsInvalidAndBoundedStreams(t *testing.T) {
	if _, err := decodeSZDD(&starfile.Bytes{Name: "short", Data: []byte("SZDD")}, 1024); err == nil {
		t.Fatal("truncated header was accepted")
	}
	invalid := szddTestFile(1, []byte{1, 'x'})
	invalid.Data[0] = 'X'
	if _, err := decodeSZDD(invalid, 1024); err == nil {
		t.Fatal("invalid signature was accepted")
	}
	if _, err := decodeSZDD(szddTestFile(4096, []byte{1, 'x'}), 64); err == nil {
		t.Fatal("oversized output was accepted")
	}
	if _, err := decodeSZDD(szddTestFile(2, []byte{1, 'x'}), 1024); err == nil {
		t.Fatal("truncated payload was accepted")
	}
}
