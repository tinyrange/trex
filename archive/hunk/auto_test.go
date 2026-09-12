package hunk

import (
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestAutoGenerations(t *testing.T) {
	for format, data := range map[string][]byte{"hunk_objects": objectFixture(), "hunk_load": loadFixture()} {
		root := auto.Open(&starfile.Bytes{Data: data}, "", auto.Options{})
		meta, err := root.Metadata()
		if err != nil || meta.Format != format {
			t.Fatal(meta, err)
		}
		children, err := root.Children()
		if err != nil || len(children) != 1 {
			t.Fatal(children, err)
		}
	}
}
