package adapter

import (
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestRecordViews(t *testing.T) {
	data := &starfile.Bytes{Data: []byte("payload")}
	entry := func(name string, missing bool) starlark.Value {
		var file starlark.Value = data
		if missing {
			file = starlark.None
		}
		return starfile.NewRecord(starlark.StringDict{"name": starlark.Bytes(name), "data": file, "resource": file, "missing_contents": starlark.Bool(missing)})
	}
	value := starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList([]starlark.Value{entry("same", false), entry("same", false), entry("missing", true)})})
	view, err := Parsed(value, auto.Options{MaxEntries: 10, MaxDepth: 10})
	if err != nil {
		t.Fatal(err)
	}
	root := auto.FromView(view, "", auto.Options{})
	for _, path := range []string{"same/1/data", "same/2/resource"} {
		node, err := root.Resolve(path)
		if err != nil {
			t.Fatal(err)
		}
		if node.Reader() != data {
			t.Fatal("reader not preserved", path)
		}
	}
	node, err := root.Resolve("same")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := node.Metadata()
	if err != nil || !meta.Container || meta.Readable {
		t.Fatal(meta, err)
	}
	node, err = root.Resolve("missing")
	if err != nil {
		t.Fatal(err)
	}
	meta, err = node.Metadata()
	if err != nil || meta.Readable || meta.Attributes["missing_contents"] != true {
		t.Fatal(meta, err)
	}
}

func TestRecordUnsafeDuplicate(t *testing.T) {
	for _, name := range []string{"a/../same", "same\x00"} {
		_, err := recordTree([]auto.Entry{{Name: "same", Kind: "file"}, {Name: name, Kind: "file"}}, auto.Options{})
		if err == nil {
			t.Fatal("accepted unsafe duplicate", name)
		}
	}
}

func TestDirectoryMetadataRecords(t *testing.T) {
	view, err := recordTree([]auto.Entry{{Name: "dir", Kind: "directory"}, {Name: "dir", Kind: "file"}, {Name: "dir/child", Kind: "file"}}, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	root := auto.FromView(view, "", auto.Options{})
	children, err := root.Children()
	if err != nil || len(children) != 3 {
		t.Fatal(children, err)
	}
	for i, node := range children {
		meta, err := node.Metadata()
		if err != nil || meta.Attributes["original_path"] == nil {
			t.Fatal(i, meta, err)
		}
	}
}

func TestResourceOccurrencePaths(t *testing.T) {
	view, err := recordTree([]auto.Entry{{Name: "54455354/128", Kind: "file"}, {Name: "54455354/128/2", Kind: "file"}}, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	children, err := auto.FromView(view, "", auto.Options{}).Children()
	if err != nil || len(children) != 2 || children[0].Name() != "1" {
		t.Fatal(children, err)
	}
}

func TestTreePreservesExplicitDirectoryView(t *testing.T) {
	data := &starfile.Bytes{Data: []byte("child")}
	view, err := auto.Tree([]auto.Entry{{Name: "dir", Kind: "directory", View: auto.ViewFunc(func() ([]auto.Entry, error) { return []auto.Entry{{Name: "child", Kind: "file", Reader: data}}, nil })}}, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	node, err := auto.FromView(view, "", auto.Options{}).Resolve("dir/child")
	if err != nil || node.Reader() != data {
		t.Fatal(node, err)
	}
}
