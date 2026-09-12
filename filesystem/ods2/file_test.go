package ods2

import (
	"bytes"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"testing"
)

func TestMappedFile(t *testing.T) {
	b := make([]byte, 4*512)
	copy(b[512:], bytes.Repeat([]byte{'B'}, 512))
	copy(b[1536:], bytes.Repeat([]byte{'A'}, 512))
	f, err := MapFile(&starfile.Bytes{Data: b}, []Extent{{LBN: 3, Blocks: 1}, {LBN: 1, Blocks: 1}}, 600)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 120)
	n, err := f.ReadAt(p, 500)
	if n != 100 || err != io.EOF || !bytes.Equal(p[:12], bytes.Repeat([]byte{'A'}, 12)) || !bytes.Equal(p[12:100], bytes.Repeat([]byte{'B'}, 88)) {
		t.Fatal(n, err, p)
	}
	b[1536] = 'C'
	if n, err := f.ReadAt(p[:1], 0); n != 1 || err != nil || p[0] != 'C' {
		t.Fatal("copied extent", n, err)
	}
	if _, err := f.ReadAt(p, -1); err == nil {
		t.Fatal("negative offset")
	}
	if n, err := f.ReadAt(p, 600); n != 0 || err != io.EOF {
		t.Fatal(n, err)
	}
	if _, err := f.WriteAt(p, 0); err == nil {
		t.Fatal("writable")
	}
	for _, ext := range [][]Extent{{{LBN: 4, Blocks: 1}}, {{LBN: 0, Blocks: 0}}, {{LBN: 0xffffffff, Blocks: 1}}} {
		if _, err := MapFile(&starfile.Bytes{Data: b}, ext, 0); err == nil {
			t.Fatal("bad extent", ext)
		}
	}
	if _, err := MapFile(&starfile.Bytes{Data: b}, []Extent{{LBN: 0, Blocks: 1}}, 513); err == nil {
		t.Fatal("EOF exceeds allocation")
	}
	if f, err := MapFile(&starfile.Bytes{Data: b}, nil, 0); err != nil || f.Size() != 0 {
		t.Fatal(f, err)
	}
}
