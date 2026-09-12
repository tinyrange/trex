package ufs

import (
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestAutoView(t *testing.T) {
	source := &starfile.Bytes{Data: fixture(binary.LittleEndian)}
	root := auto.Open(source, "no-extension", auto.Options{})
	meta, err := root.Metadata()
	if err != nil || meta.Format != "ufs" {
		t.Fatalf("%+v %v", meta, err)
	}
	children, err := root.Children()
	if err != nil || len(children) == 0 {
		t.Fatalf("%v %v", children, err)
	}

}
