package nsis

import (
	"bytes"
	"encoding/binary"
	"errors"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/ulikunitz/xz/lzma"
	"go.starlark.net/starlark"
	"testing"
)

func solidFixture(t *testing.T) []byte {
	t.Helper()
	meta := metadataFixture()
	decoded := binary.LittleEndian.AppendUint32(nil, uint32(len(meta)))
	decoded = append(decoded, meta...)
	decoded = binary.LittleEndian.AppendUint32(decoded, 3)
	decoded = append(decoded, "abc"...)
	decoded = binary.LittleEndian.AppendUint32(decoded, 2)
	decoded = append(decoded, "de"...)
	var compressed bytes.Buffer
	w, err := lzma.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(decoded); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	encoded := compressed.Bytes()
	b := make([]byte, 512+28)
	copy(b, "MZ")
	copy(b[516:], signature)
	binary.LittleEndian.PutUint32(b[532:], uint32(len(meta)))
	b = append(b, encoded[:5]...)
	b = append(b, encoded[13:]...)
	b = append(b, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(b[536:], uint32(len(b)-512))
	return b
}
func TestSolidLZMA(t *testing.T) {
	b := solidFixture(t)
	a, err := Open(&starfile.Bytes{Data: b}, Options{}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if a.Listing.HeaderCompression != "lzma-solid" || len(a.Listing.Entries) != 3 {
		t.Fatalf("%+v", a.Listing)
	}
	for i, want := range []string{"abc", "de", "de"} {
		f, ok, err := a.Get(starlark.String(MemberName(a.Listing.Entries[i])))
		if err != nil || !ok {
			t.Fatal(err)
		}
		data, err := starfile.ReadAll(f.(starfile.File))
		if err != nil || string(data) != want {
			t.Fatalf("%q %v", data, err)
		}
	}
	if _, err := List(&starfile.Bytes{Data: b}, Options{MaxSolidBytes: 100}); !errors.Is(err, ErrLimit) {
		t.Fatalf("limit: %v", err)
	}
	// A truncated range stream must not be accepted as an ordinary DEFLATE block.
	bad := append([]byte(nil), b[:len(b)-10]...)
	binary.LittleEndian.PutUint32(bad[536:], uint32(len(bad)-512))
	if _, err := List(&starfile.Bytes{Data: bad}, Options{}); err == nil {
		t.Fatal("truncated solid stream accepted")
	}
}
