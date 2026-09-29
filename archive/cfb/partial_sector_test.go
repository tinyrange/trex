package cfb

import (
	"bytes"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"testing"
)

func TestPartialFinalStreamSector(t *testing.T) {
	b := append(fixture(), byte(42))
	binary.LittleEndian.PutUint32(b[512+44:], 12)
	binary.LittleEndian.PutUint32(b[512+48:], end)
	binary.LittleEndian.PutUint32(b[1024+256+120:], 4097)
	a, err := Open(&starfile.Bytes{Data: b})
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(a.Lookup("Large"))
	if err != nil || !bytes.Equal(got, b[2560:]) {
		t.Fatalf("stream read: %v", err)
	}
	// Losing the last referenced byte is corruption, not missing padding.
	if _, err := Open(&starfile.Bytes{Data: b[:len(b)-1]}); err == nil {
		t.Fatal("accepted missing stream byte")
	}
	// A partial sector earlier than EOF must also have all referenced bytes.
	binary.LittleEndian.PutUint32(b[1024+256+120:], 4098)
	if _, err := Open(&starfile.Bytes{Data: b}); err == nil || !strings.Contains(err.Error(), "truncated stream") {
		t.Fatalf("got %v", err)
	}
}

func TestPartialMetadataSectorRejected(t *testing.T) {
	b := fixture()
	// Move the directory into a partial final sector: unlike stream padding,
	// the complete directory sector is required.
	b = append(b, b[1024:1152]...)
	binary.LittleEndian.PutUint32(b[48:], 12)
	binary.LittleEndian.PutUint32(b[512+48:], end)
	if _, err := Open(&starfile.Bytes{Data: b}); err == nil {
		t.Fatal("accepted truncated directory sector")
	}
}
