package bru

import (
	"github.com/tinyrange/trex/auto"
	"testing"
)

func TestAutoArchive(t *testing.T) {
	source, _ := fixture()
	root := auto.Open(source, "", auto.Options{})
	meta, err := root.Metadata()
	if err != nil || meta.Format != "bru" {
		t.Fatal(meta, err)
	}
	children, err := root.Children()
	if err != nil || len(children) == 0 {
		t.Fatal(children, err)
	}
	source.Data[128] ^= 1
	if _, err := auto.Identify(source, auto.Options{}); err == nil {
		t.Fatal("accepted corrupt checksum")
	}
}
