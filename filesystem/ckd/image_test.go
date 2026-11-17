package ckd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestBuildImagePreservesRecordsAndRandomAccess(t *testing.T) {
	records := [][]Record{
		{{Number: 0, Data: make([]byte, 8)}, {Number: 1, Key: []byte("key"), Data: []byte("boot")}},
		{{Head: 1, Number: 0, Data: make([]byte, 8)}, {Head: 1, Number: 1}},
		{{Cylinder: 1, Number: 0, Data: make([]byte, 8)}, {Cylinder: 1, Number: 7, Data: []byte("data")}},
		{{Cylinder: 1, Head: 1, Number: 0, Data: make([]byte, 8)}, {Cylinder: 1, Head: 1, Number: 1}},
	}
	img, err := BuildImage(2, 2, testTrackSize, 0x90, map[uint32][]Record{0: records[0], 2: records[2]})
	if err != nil {
		t.Fatal(err)
	}
	want := image(records)
	// Existing independent fixture writer predates this constructor. Verify
	// every byte through unaligned reads crossing header/track/EOF boundaries.
	var got []byte
	for off := int64(0); off < img.Size(); off += 137 {
		b := bytes.Repeat([]byte{0xaa}, 137)
		n, err := img.ReadAt(b, off)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		got = append(got, b[:n]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("uncompressed image differs from independent CKD fixture")
	}
	records[0][1].Data[0] = 'X'
	b := make([]byte, len(want))
	img.ReadAt(b, 0)
	if !bytes.Equal(b, want) {
		t.Fatal("image retained mutable record input")
	}
	disk, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := disk.Walk(context.Background(), nil)
	if err != nil || stats.Tracks != 4 || stats.Records != 8 {
		t.Fatalf("roundtrip walk: %+v %v", stats, err)
	}
	if _, err := img.ReadAt(make([]byte, 1), -1); err == nil {
		t.Fatal("negative read accepted")
	}
	if n, err := img.ReadAt(make([]byte, 1), img.Size()); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("bad EOF")
	}
}

func TestBuildImageRejectsInvalidGeometryAndRecords(t *testing.T) {
	for _, g := range [][3]uint32{{0, 2, 2048}, {65537, 2, 2048}, {1, 0, 2048}, {1, 257, 2048}, {1, 2, 36}, {1, 2, 1<<20 + 1}} {
		if _, err := BuildImage(g[0], g[1], g[2], 0x80, nil); err == nil {
			t.Fatal("invalid geometry accepted", g)
		}
	}
	for _, records := range map[string]map[uint32][]Record{
		"outside":  {2: nil},
		"key":      {0: {{Key: make([]byte, 256)}}},
		"data":     {0: {{Data: make([]byte, 65536)}}},
		"overflow": {0: {{Data: make([]byte, 2048)}}},
	} {
		if _, err := BuildImage(1, 2, 2048, 0x80, records); err == nil {
			t.Fatal("invalid records accepted")
		}
	}
}
