package star

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

func TestBinaryXMLParsesUTF8AndUTF16(t *testing.T) {
	const source = `<?xml version="1.0" encoding="UTF-16"?><ROOT mode="setup"><ITEM>alpha</ITEM><ITEM>beta</ITEM></ROOT>`
	utf16Data := []byte{0xff, 0xfe}
	for _, unit := range utf16.Encode([]rune(source)) {
		var encoded [2]byte
		binary.LittleEndian.PutUint16(encoded[:], unit)
		utf16Data = append(utf16Data, encoded[:]...)
	}
	for _, data := range [][]byte{
		[]byte(strings.Replace(source, ` encoding="UTF-16"`, "", 1)),
		append([]byte{0xef, 0xbb, 0xbf}, []byte(strings.Replace(source, ` encoding="UTF-16"`, "", 1))...),
		utf16Data,
	} {
		value, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(data)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		root := value.(*binaryXMLDocument).root
		if root.name != "ROOT" || root.namespace != "" {
			t.Fatalf("root = {%q %q}", root.namespace, root.name)
		}
		attribute, err := root.attributeBuiltin(nil, nil, starlark.Tuple{starlark.String("mode")}, nil)
		if err != nil || attribute != starlark.String("setup") {
			t.Fatalf("mode = %v, %v", attribute, err)
		}
		children, err := root.childrenNamedBuiltin(nil, nil, starlark.Tuple{starlark.String("ITEM")}, nil)
		if err != nil || children.(*starlark.List).Len() != 2 {
			t.Fatalf("children = %v, %v", children, err)
		}
		if got := root.allText(); got != "alphabeta" {
			t.Fatalf("text = %q", got)
		}
	}
}

func TestBinaryXMLRejectsMalformedAndBoundedInput(t *testing.T) {
	for _, test := range []struct {
		name   string
		script string
		match  string
	}{
		{"malformed", `binary.xml(b"<ROOT>")`, "parse"},
		{"depth", `binary.xml(b"<A><B/></A>", max_depth=1)`, "nesting depth"},
		{"nodes", `binary.xml(b"<A><B/></A>", max_nodes=1)`, "node count"},
		{"size", `binary.xml(b"<A/>", maximum=3)`, "input size"},
		{"prefix", `binary.xml(b"<p:A/>")`, "undeclared namespace prefix"},
		{"outside", `binary.xml(b"<A/>tail")`, "character data after root"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var input starlark.Bytes
			var kwargs []starlark.Tuple
			switch test.name {
			case "malformed":
				input = "<ROOT>"
			case "depth":
				input = "<A><B/></A>"
				kwargs = []starlark.Tuple{{starlark.String("max_depth"), starlark.MakeInt(1)}}
			case "nodes":
				input = "<A><B/></A>"
				kwargs = []starlark.Tuple{{starlark.String("max_nodes"), starlark.MakeInt(1)}}
			case "size":
				input = "<A/>"
				kwargs = []starlark.Tuple{{starlark.String("maximum"), starlark.MakeInt(3)}}
			case "prefix":
				input = "<p:A/>"
			case "outside":
				input = "<A/>tail"
			}
			_, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{input}, kwargs)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("got error %v, want substring %q", err, test.match)
			}
		})
	}
}

func TestDecodeXMLBytesRejectsUnpairedSurrogate(t *testing.T) {
	data := []byte{0xff, 0xfe, 0x00, 0xd8}
	if _, err := decodeXMLBytes(data); err == nil {
		t.Fatal("decodeXMLBytes accepted an unpaired surrogate")
	}
	valid := utf16.Encode([]rune("<?xml version=\"1.0\"?><A/>"))
	data = []byte{0xff, 0xfe}
	for _, unit := range valid {
		data = append(data, byte(unit), byte(unit>>8))
	}
	if _, err := decodeXMLBytes(data); err != nil {
		t.Fatalf("decodeXMLBytes valid UTF-16: %v", err)
	}
}

func TestBinaryXMLPreservesNamespacesAndMixedContent(t *testing.T) {
	const source = `<?xml version="1.0"?><!--before--><pkc:Root xmlns:pkc="urn:product" xml:lang="en">left<pkc:Child id="1"/>right<!--inside--></pkc:Root>`
	value, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(source)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	document := value.(*binaryXMLDocument)
	root := document.root
	if root.prefix != "pkc" || root.namespace != "urn:product" || root.directText() != "leftright" || root.allText() != "leftright" {
		t.Fatalf("root prefix=%q namespace=%q direct=%q text=%q", root.prefix, root.namespace, root.directText(), root.allText())
	}
	if got := root.attributes[0]; got.prefix != "xmlns" || got.namespace != legacyXMLNSMarker || got.name != "pkc" {
		t.Fatalf("namespace declaration = %#v", got)
	}
	if got := root.attributes[1]; got.prefix != "xml" || got.namespace != xmlNamespace {
		t.Fatalf("xml attribute = %#v", got)
	}
	data, err := renderXML(document.prefix, root, document.suffix, defaultBinaryXMLLimit)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{`<?xml version="1.0"?>`, `<!--before-->`, `<pkc:Root xmlns:pkc="urn:product" xml:lang="en">`, `left<pkc:Child id="1"/>right<!--inside-->`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("serialized XML %q does not contain %q", text, expected)
		}
	}
	if _, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(data)}, nil); err != nil {
		t.Fatalf("round trip: %v", err)
	}
}

func TestBinaryXMLImmutableEditing(t *testing.T) {
	const source = `<p:Root xmlns:p="urn:test"><p:Items><p:Item id="1">one</p:Item><p:Item id="2">two</p:Item></p:Items><p:Tail>old</p:Tail></p:Root>`
	value, err := binaryXMLBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(source)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	document := value.(*binaryXMLDocument)
	root := document.root
	children := root.childNodes()
	items := children[0]
	selected := items.childNodes()[1]
	updatedItemsValue, err := items.withChildrenBuiltin(nil, nil, starlark.Tuple{starlark.NewList([]starlark.Value{selected})}, nil)
	if err != nil {
		t.Fatal(err)
	}
	updatedTailValue, err := children[1].withTextBuiltin(nil, nil, starlark.Tuple{starlark.String(`new & <value>`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	updatedRootValue, err := root.withChildrenBuiltin(nil, nil, starlark.Tuple{starlark.NewList([]starlark.Value{
		updatedItemsValue, updatedTailValue,
	})}, nil)
	if err != nil {
		t.Fatal(err)
	}
	updated := updatedRootValue.(*binaryXMLNode)
	data, err := renderXML(document.prefix, updated, document.suffix, defaultBinaryXMLLimit)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, `id="1"`) || !strings.Contains(text, `<p:Item id="2">two</p:Item>`) || !strings.Contains(text, `new &amp; &lt;value&gt;`) {
		t.Fatalf("updated XML = %q", text)
	}
	if len(items.childNodes()) != 2 || children[1].allText() != "old" {
		t.Fatal("immutable edit changed source tree")
	}
	if _, err := renderXML(document.prefix, updated, document.suffix, len(data)-1); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("bounded render error = %v", err)
	}
}
