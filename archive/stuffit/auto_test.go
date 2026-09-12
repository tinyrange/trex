package stuffit

import (
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestAutoView(t *testing.T) {
	source := &starfile.Bytes{Data: fixture()}
	root := auto.Open(source, "no-extension", auto.Options{})
	meta, err := root.Metadata()
	if err != nil || meta.Format != "stuffit" {
		t.Fatalf("%+v %v", meta, err)
	}
	children, err := root.Children()
	if err != nil || len(children) == 0 {
		t.Fatalf("%v %v", children, err)
	}
	node, err := root.Resolve("F/resource")
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, node.Reader().Size())
	_, err = node.Reader().ReadAt(data, 0)
	if err != nil || string(data) != "R" {
		t.Fatalf("%q %v", data, err)
	}
}
