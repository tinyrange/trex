package star

import (
	"github.com/tinyrange/trex/auto"
	"go.starlark.net/starlark"
	"testing"
)

func TestStructuredAttributes(t *testing.T) {
	tree, err := auto.Tree([]auto.Entry{{Name: "object", Kind: "directory", Attributes: map[string]any{"nested": map[string]any{"address": uint64(0xffffffffffffffff), "complete": false}}}}, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := auto.FromView(tree, "", auto.Options{}).Resolve("object")
	if err != nil {
		t.Fatal(err)
	}
	m, err := (&Value{n}).Attr("metadata")
	if err != nil {
		t.Fatal(err)
	}
	attrs, _, err := m.(*starlark.Dict).Get(starlark.String("attributes"))
	if err != nil {
		t.Fatal(err)
	}
	nested, _, _ := attrs.(*starlark.Dict).Get(starlark.String("nested"))
	address, _, _ := nested.(*starlark.Dict).Get(starlark.String("address"))
	v, ok := address.(starlark.Int).Uint64()
	if !ok || v != ^uint64(0) {
		t.Fatal(address)
	}
}
