package vmsbackup

import (
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestAutoMissingContents(t *testing.T) {
	data := testBlock(1, 1)
	clear(data[256:])
	metadata := fileMetadata(600)
	binary.LittleEndian.PutUint16(data[256:], uint16(len(metadata)))
	binary.LittleEndian.PutUint16(data[258:], 3)
	copy(data[272:], metadata)
	padding := 272 + len(metadata)
	binary.LittleEndian.PutUint16(data[padding:], uint16(len(data)-padding-16))
	sealBlock(data)
	root := auto.Open(&starfile.Bytes{Data: data}, "", auto.Options{})
	meta, err := root.Metadata()
	if err != nil || meta.Format != "vmsbackup" {
		t.Fatal(meta, err)
	}
	children, err := root.Children()
	if err != nil || len(children) != 1 {
		t.Fatal(children, err)
	}
	meta, err = children[0].Metadata()
	if err != nil || meta.Readable || meta.Attributes["missing_contents"] != true {
		t.Fatal(meta, err)
	}
}
