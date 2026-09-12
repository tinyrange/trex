package apm

import (
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestAutoPartitions(t *testing.T) {
	root := auto.Open(&starfile.Bytes{Data: fixture(512)}, "", auto.Options{})
	node, err := root.Resolve("blocks-512/partition-2")
	if err != nil {
		t.Fatal(err)
	}
	var data [4]byte
	_, err = node.Reader().ReadAt(data[:], 0)
	if err != nil || string(data[:]) != "data" {
		t.Fatal(data, err)
	}
	node, err = root.Resolve("blocks-512/partition-3")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := node.Metadata()
	if err != nil || meta.Readable || meta.Attributes["complete"] != false {
		t.Fatal(meta, err)
	}
	root = auto.Open(&starfile.Bytes{Data: fixture(512)}, "", auto.Options{MaxEntries: 2})
	if _, err = root.Children(); err == nil {
		t.Fatal("entry limit ignored")
	}
}
