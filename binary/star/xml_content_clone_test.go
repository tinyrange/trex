package star

import (
	"bytes"
	"go.starlark.net/starlark"
	"testing"
)

// Editing shares immutable non-child records as well as child nodes. Preserve
// every mixed-content kind and its position without changing the source tree.
func TestXMLMixedContentCloneOwnership(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE root><!--before--><root>left<a/>right<!--inside--><?work detail?><b/></root><?tail?>`)
	doc, err := parseBinaryXML(input, 256, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	before, err := renderXML(doc.prefix, doc.root, doc.suffix, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for i := range input {
		input[i] = 'x'
	}
	replacement, err := parseBinaryXML([]byte(`<new/>`), 256, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	edited, err := doc.root.withChildrenBuiltin(nil, nil, starlark.Tuple{starlark.NewList([]starlark.Value{replacement.root})}, nil)
	if err != nil {
		t.Fatal(err)
	}
	edited, err = edited.(*binaryXMLNode).withTextBuiltin(nil, nil, starlark.Tuple{starlark.String("changed & text")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := renderXML(doc.prefix, edited.(*binaryXMLNode), doc.suffix, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	want := `<?xml version="1.0"?><!DOCTYPE root><!--before--><root>changed &amp; text<new/><!--inside--><?work detail?></root><?tail?>`
	if string(actual) != want {
		t.Fatalf("edited XML = %s", actual)
	}
	after, err := renderXML(doc.prefix, doc.root, doc.suffix, 1<<20)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("source changed: %s, %v", after, err)
	}
	if _, err := parseBinaryXML(actual, 256, 1<<20, false); err != nil {
		t.Fatal(err)
	}
}
