package star

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestBinaryXMLAttributeMapNamespaces(t *testing.T) {
	v, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{starlark.String(`<r xmlns="urn:default" xmlns:p="urn:p" xmlns:q="urn:p" a="local" p:a="foreign" p:b="second"><child a="child"/></r>`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	root := v.(*binaryXMLDocument).root
	for _, tc := range []struct {
		namespace string
		strict    bool
		expected  string
		fail      bool
	}{
		{"", false, `{"a": "local"}`, false},
		{"urn:p", false, `{"a": "foreign", "b": "second"}`, false},
		{"urn:absent", false, `{}`, false},
		{"", true, "", true}, {"urn:p", true, "", true},
	} {
		got, err := root.attributeMapBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("namespace"), starlark.String(tc.namespace)}, {starlark.String("strict"), starlark.Bool(tc.strict)}})
		if (err != nil) != tc.fail {
			t.Fatalf("%+v: %v", tc, err)
		}
		if !tc.fail && got.String() != tc.expected {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
	// Results own their dictionaries: callers cannot edit parsed attributes.
	got, err := root.attributeMapBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = got.(*starlark.Dict).SetKey(starlark.String("a"), starlark.String("changed"))
	actual, err := root.attributeBuiltin(nil, nil, starlark.Tuple{starlark.String("a")}, nil)
	if err != nil || actual != starlark.String("local") {
		t.Fatal(actual, err)
	}
	child := root.childNodes()[0]
	got, err = child.attributeMapBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("strict"), starlark.True}})
	if err != nil || got.String() != `{"a": "child"}` {
		t.Fatal(got, err)
	}
}

func TestBinaryXMLAttributeMapRejectsDuplicateExpandedNames(t *testing.T) {
	// XML tokens can carry duplicate attributes; the projection must not hide
	// them, including two prefixes bound to the same expanded namespace.
	for _, source := range []string{`<r a="1" a="2"/>`, `<r xmlns:p="urn:p" xmlns:q="urn:p" p:a="1" q:a="2"/>`} {
		v, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{starlark.String(source)}, nil)
		if err != nil {
			continue
		} // A stricter parser rejecting them is also safe.
		ns := ""
		if len(source) > 30 {
			ns = "urn:p"
		}
		got, err := v.(*binaryXMLDocument).root.attributeMapBuiltin(nil, nil, starlark.Tuple{starlark.String(ns)}, nil)
		if err == nil || got != nil {
			t.Fatalf("duplicate accepted: %s => %v", source, got)
		}
	}
}

func BenchmarkBinaryXMLAttributeMap(b *testing.B) {
	v, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{starlark.String(`<r name="package" version="10.0.1.2" publicKeyToken="31bf3856ad364e35" processorArchitecture="amd64" language="neutral"/>`)}, nil)
	if err != nil {
		b.Fatal(err)
	}
	root := v.(*binaryXMLDocument).root
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := root.attributeMapBuiltin(nil, nil, nil, nil); err != nil {
			b.Fatal(err)
		}
	}
}
