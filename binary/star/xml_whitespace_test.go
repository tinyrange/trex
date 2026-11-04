package star

import (
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestBinaryXMLDiscardWhitespacePolicy(t *testing.T) {
	source := " \n<?probe keep?><!--outside--><r xmlns:f=\"urn:foreign\">\n" +
		"<drop a=\"  \" f:space=\"preserve\"> \t\n</drop>" +
		"<preserve xml:space=\"preserve\"> <child>\t</child><reset xml:space=\"default\">\n<x/>\n</reset> </preserve>" +
		"<unknown xml:space=\"custom\"> </unknown>" +
		"<mixed> left <b/> right </mixed><unicode>\u00a0</unicode><!--inside--><?tail keep?>\n</r>\n"
	parse := func(discard bool) *binaryXMLDocument {
		t.Helper()
		value, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(source)}, []starlark.Tuple{{starlark.String("discard_whitespace"), starlark.Bool(discard)}})
		if err != nil {
			t.Fatal(err)
		}
		return value.(*binaryXMLDocument)
	}
	original := parse(false)
	compact := parse(true)
	byName := map[string]*binaryXMLNode{}
	for _, n := range compact.root.childNodes() {
		byName[n.name] = n
	}
	if byName["drop"].allText() != "" || byName["drop"].attributes[0].value != "  " {
		t.Fatal("discard changed attributes or retained indentation")
	}
	preserve := byName["preserve"]
	if preserve.directText() != "  " || preserve.childNodes()[0].allText() != "\t" || preserve.childNodes()[1].allText() != "" {
		t.Fatal("xml:space inheritance/reset lost")
	}
	if byName["unknown"].allText() != " " || byName["mixed"].allText() != " left  right " || byName["unicode"].allText() != "\u00a0" {
		t.Fatal("non-indentation content changed")
	}
	if original.root.childNodes()[0].allText() != " \t\n" || original.root.directText() != "\n\n" {
		t.Fatal("default parsing lost whitespace")
	}
	data, err := renderXML(compact.prefix, compact.root, compact.suffix, defaultBinaryXMLLimit)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"<?probe keep?>", "<!--outside-->", "<!--inside-->", "<?tail keep?>"} {
		if !strings.Contains(string(data), text) {
			t.Fatalf("lost %s", text)
		}
	}
	if len(compact.prefix) != 2 || len(compact.suffix) != 0 {
		t.Fatal("document indentation retained")
	}
}

func TestBinaryXMLDiscardWhitespaceRetainsBoundsAndErrors(t *testing.T) {
	for _, tc := range []struct {
		source string
		limit  string
		value  int
	}{
		{" <a><b/></a> ", "max_nodes", 1}, {" <a><b/></a> ", "max_depth", 1}, {" <a/> ", "maximum", 3},
		{" <a></b> ", "max_nodes", 10}, {" <a/> bad ", "max_nodes", 10}, {" <a/><b/> ", "max_nodes", 10}, {" <u:a/> ", "max_nodes", 10},
	} {
		value, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(tc.source)}, []starlark.Tuple{{starlark.String("discard_whitespace"), starlark.True}, {starlark.String(tc.limit), starlark.MakeInt(tc.value)}})
		if err == nil || value != nil {
			t.Fatalf("accepted %q with %s=%d: %v %v", tc.source, tc.limit, tc.value, value, err)
		}
	}
}

func BenchmarkBinaryXMLIndentation(b *testing.B) {
	source := starlark.Bytes("<root>\n" + strings.Repeat("  <node name=\"value\">\n    <child/>\n  </node>\n", 2048) + "</root>")
	for _, mode := range []struct {
		name    string
		discard bool
	}{{"retained", false}, {"discarded", true}} {
		b.Run(mode.name, func(b *testing.B) {
			kwargs := []starlark.Tuple{{starlark.String("discard_whitespace"), starlark.Bool(mode.discard)}}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{source}, kwargs); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
