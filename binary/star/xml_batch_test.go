package star

import (
	"reflect"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestBinaryXMLManyMatchesSerial(t *testing.T) {
	inputs := []starlark.Value{
		starlark.String(`<a xmlns="urn:a" xmlns:p="urn:p" p:v="1"> <b/>text </a>`),
		starlark.Bytes("\xff\xfe<\x00b\x00/\x00>\x00"),
		starlark.String(`<a xml:space="preserve"> <b xml:space="default"> </b> </a>`),
		starlark.String(`<a xmlns="urn:a" xmlns:p="urn:p" p:v="1"> <b/>text </a>`),
	}
	for _, workers := range []int{1, 4, 8} {
		for _, discard := range []bool{false, true} {
			kwargs := []starlark.Tuple{{starlark.String("discard_whitespace"), starlark.Bool(discard)}}
			v, err := binaryXMLManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList(inputs)}, append(kwargs, starlark.Tuple{starlark.String("workers"), starlark.MakeInt(workers)}))
			if err != nil {
				t.Fatal(err)
			}
			list := v.(*starlark.List)
			for i, input := range inputs {
				serial, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{input}, kwargs)
				if err != nil || !reflect.DeepEqual(serial, list.Index(i)) {
					t.Fatalf("input %d differs: %v", i, err)
				}
			}
			if list.Index(0) == list.Index(3) {
				t.Fatal("duplicate documents alias")
			}
		}
	}
	empty, err := binaryXMLManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList(nil)}, nil)
	if err != nil || empty.(*starlark.List).Len() != 0 {
		t.Fatalf("empty: %v %v", empty, err)
	}
}

func TestBinaryXMLManyBoundsAndErrors(t *testing.T) {
	for _, test := range []struct {
		key   string
		value int
		input string
	}{
		{"workers", 0, "<a/>"}, {"workers", 9, "<a/>"},
		{"maximum", 3, "<a/>"}, {"max_depth", 1, "<a><b/></a>"},
		{"max_nodes", 1, "<a><b/></a>"}, {"total_maximum", 7, "<a/>"},
		{"total_maximum", -1, "<a/>"}, {"total_maximum", (256 << 20) + 1, "<a/>"},
	} {
		v, err := binaryXMLManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList([]starlark.Value{starlark.String(test.input), starlark.String(test.input)})}, []starlark.Tuple{{starlark.String(test.key), starlark.MakeInt(test.value)}})
		if v != nil || err == nil {
			t.Fatalf("accepted %s=%d: %v %v", test.key, test.value, v, err)
		}
	}
	inputs := []starlark.Value{starlark.String("<good/>"), starlark.String("<a>"), starlark.String("<p:a/>")}
	for range 10 {
		v, err := binaryXMLManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList(inputs)}, nil)
		if v != nil || err == nil || !strings.Contains(err.Error(), "input 1:") {
			t.Fatalf("nondeterministic partial result: %v %v", v, err)
		}
	}
	inputs = make([]starlark.Value, 4097)
	for i := range inputs {
		inputs[i] = starlark.String("<a/>")
	}
	if v, err := binaryXMLManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList(inputs)}, nil); v != nil || err == nil {
		t.Fatal("batch bound")
	}
	if v, err := binaryXMLManyBuiltin(nil, nil, starlark.Tuple{starlark.NewList([]starlark.Value{starlark.None})}, nil); v != nil || err == nil {
		t.Fatal("input type")
	}
}
