package compactpro

import (
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestAutoArchive(t *testing.T) {
	root := auto.Open(&starfile.Bytes{Data: archiveSample()}, "", auto.Options{})
	meta, err := root.Metadata()
	if err != nil || meta.Format != "compactpro" {
		t.Fatal(meta, err)
	}
	children, err := root.Children()
	if err != nil || len(children) == 0 {
		t.Fatal(children, err)
	}
	root = auto.Open(&starfile.Bytes{Data: archiveSample()}, "", auto.Options{MaxExpandedBytes: 1})
	if _, err := root.Children(); err == nil {
		t.Fatal("decoded limit ignored")
	}
}
