package star

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestXMLSelectSharesNodesInDocumentOrder(t *testing.T) {
	v, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{starlark.String(`<a xmlns="urn:a"><b/><x xmlns="urn:other"><a/><b xmlns="urn:a"/></x><a/><b/></a>`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	root := v.(*binaryXMLDocument).root
	names := starlark.NewList([]starlark.Value{starlark.String("b"), starlark.String("a"), starlark.String("absent")})
	options := []starlark.Tuple{{starlark.String("namespace"), starlark.String("urn:a")}, {starlark.String("include_self"), starlark.True}}
	value, err := root.selectDescendantsBuiltin(nil, nil, starlark.Tuple{names}, options)
	if err != nil {
		t.Fatal(err)
	}
	result := value.(*starlark.Dict)
	for _, name := range []string{"a", "b", "absent"} {
		var expected starlark.Tuple
		var walk func(*binaryXMLNode)
		walk = func(n *binaryXMLNode) {
			if n.name == name && n.namespace == "urn:a" {
				expected = append(expected, n)
			}
			for _, child := range n.childNodes() {
				walk(child)
			}
		}
		walk(root)
		got, _, err := result.Get(starlark.String(name))
		if err != nil {
			t.Fatal(err)
		}
		tuple := got.(starlark.Tuple)
		if len(tuple) != len(expected) {
			t.Fatalf("%s: wrong match count", name)
		}
		for i := range tuple {
			if tuple[i] != expected[i] {
				t.Fatal("selection copied or reordered nodes")
			}
		}
	}
	if err := result.SetKey(starlark.String("a"), starlark.None); err == nil {
		t.Fatal("shared selection mutable")
	}
	without, err := root.selectDescendantsBuiltin(nil, nil, starlark.Tuple{names}, options[:1])
	if err != nil {
		t.Fatal(err)
	}
	matches, _, _ := without.(*starlark.Dict).Get(starlark.String("a"))
	if len(matches.(starlark.Tuple)) != 1 {
		t.Fatal("root included by default")
	}
}
func TestXMLSelectLimitsEditedTrees(t *testing.T) {
	root := &binaryXMLNode{name: "a"}
	names := starlark.NewList([]starlark.Value{starlark.String("a")})
	for _, bad := range []*starlark.List{starlark.NewList([]starlark.Value{starlark.MakeInt(1)}), starlark.NewList([]starlark.Value{starlark.String("a"), starlark.String("a")})} {
		if v, err := root.selectDescendantsBuiltin(nil, nil, starlark.Tuple{bad}, nil); err == nil || v != nil {
			t.Fatal("invalid selector accepted")
		}
	}
	for i := 0; i < defaultBinaryXMLDepth; i++ {
		root = &binaryXMLNode{name: "a", content: []binaryXMLPart{{kind: binaryXMLChild, child: root}}}
	}
	if v, err := root.selectDescendantsBuiltin(nil, nil, starlark.Tuple{names}, nil); err == nil || v != nil {
		t.Fatal("edited depth bound not enforced")
	}
	leaf := &binaryXMLNode{name: "a"}
	dag := &binaryXMLNode{name: "a", content: []binaryXMLPart{{kind: binaryXMLChild, child: leaf}, {kind: binaryXMLChild, child: leaf}}}
	if v, err := dag.selectDescendantsBuiltin(nil, nil, starlark.Tuple{names}, []starlark.Tuple{{starlark.String("maximum"), starlark.MakeInt(2)}}); err == nil || v != nil {
		t.Fatal("repeated node occurrences bypass visit bound")
	}
}
