package star

import (
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestExplicitSourceTree(t *testing.T) {
	auto.Register("test-star-source-tree", -100, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if string(p) != "star-source-tree" {
			return nil, auto.ErrNoMatch
		}
		if o.Source == nil || o.Source.Path != "first/input" {
			t.Error("missing source path")
		}
		f, err := o.Source.File("second/data", o)
		if err != nil {
			return nil, err
		}
		return &auto.DecodedView{Reader: f, Name: "result"}, nil
	})
	tree, err := auto.Tree([]auto.Entry{{Name: "second/data", Kind: "file", Reader: &starfile.Bytes{Data: []byte("payload")}}}, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	root := &Value{auto.FromView(tree, "", auto.Options{})}
	v, err := Builtin(nil, nil, starlark.Tuple{starlark.Bytes("star-source-tree")}, []starlark.Tuple{{starlark.String("tree"), root}, {starlark.String("path"), starlark.String("first/input")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.(*Value).Node.Metadata(); err != nil {
		t.Fatal(err)
	}
	if _, err := Builtin(nil, nil, starlark.Tuple{starlark.Bytes("x")}, []starlark.Tuple{{starlark.String("tree"), root}, {starlark.String("path"), starlark.String("../input")}}); err == nil {
		t.Fatal("accepted escaping path")
	}
}
