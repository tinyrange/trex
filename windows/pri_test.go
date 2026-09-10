package windows

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestPRISchemaBuiltin(t *testing.T) {
	// Valid old-schema container with one root scope and no resource items.
	b := make([]byte, 200)
	le := binary.LittleEndian
	copy(b, "mrm_pri2")
	le.PutUint32(b[12:], 200)
	le.PutUint32(b[16:], 32)
	le.PutUint32(b[20:], 64)
	le.PutUint16(b[24:], 1)
	copy(b[32:], "[mrm_hschema]  \x00")
	le.PutUint32(b[60:], 120)
	copy(b[64:], b[32:48])
	le.PutUint32(b[88:], 120)
	p := b[96:]
	le.PutUint16(p, 1)
	le.PutUint16(p[2:], 2)
	le.PutUint16(p[4:], 2)
	le.PutUint16(p[28:], 'A')
	le.PutUint16(p[32:], 'B')
	n := p[36:]
	le.PutUint32(n[4:], 1)
	le.PutUint32(n[8:], 1)
	le.PutUint32(n[20:], 44)
	n[24+7] = 0x10
	le.PutUint32(b[176:], 0xdef5fade)
	le.PutUint32(b[180:], 120)
	le.PutUint32(b[184:], 0xdefffade)
	le.PutUint32(b[188:], 200)
	copy(b[192:], "mrm_pri2")
	globals := starlark.StringDict{"parse": Builtins()["pri_schema"], "source": &starfile.Bytes{Data: b}}
	v, err := starlark.Eval(&starlark.Thread{Name: "schema"}, "test.star", "parse(source, section_index=0)['item_count']", globals)
	if err != nil || v.String() != "0" {
		t.Fatalf("schema count: %v %v", v, err)
	}
	for _, expr := range []string{"parse(source, section_index=-1)", "parse(source, section_index=1)", "parse(source, section_index=0, max_bytes=199)", "parse(source, section_index=0)['item_name'](0)"} {
		if _, err := starlark.Eval(&starlark.Thread{Name: "bad-schema"}, "test.star", expr, globals); err == nil {
			t.Fatalf("accepted %s", expr)
		}
	}
}

func TestPRISectionsBuiltin(t *testing.T) {
	data, err := hex.DecodeString(
		"6d726d5f70726932000001007800000020000000400000000100ffff00000000" +
			"5b6d726d5f6465636e5f696e666f5d0000000000000000000000000028000000" +
			"00000000000000000000000000000000000000000000000000000000000000000000000000000000" +
			"defaffde780000006d726d5f70726932")
	if err != nil {
		t.Fatal(err)
	}
	globals := starlark.StringDict{"parse": Builtins()["pri_sections"], "source": &starfile.Bytes{Data: data}}
	v, err := starlark.Eval(&starlark.Thread{Name: "pri"}, "test.star", "parse(source)[0]", globals)
	if err != nil {
		t.Fatal(err)
	}
	d := v.(*starlark.Dict)
	tag, _, _ := d.Get(starlark.String("type"))
	if tag != starlark.String("[mrm_decn_info]") {
		t.Fatalf("type: %s", tag)
	}
	payload, _, _ := d.Get(starlark.String("data"))
	if payload.(starfile.File).Size() != 40 {
		t.Fatal("incorrect section size")
	}
	for _, expression := range []string{"parse(source, max_bytes=119)", "parse(source, max_bytes=-1)", "parse('not a file')"} {
		if _, err := starlark.Eval(&starlark.Thread{Name: "bad-pri"}, "test.star", expression, globals); err == nil {
			t.Fatalf("accepted %s", expression)
		}
	}
}

func TestPRIResourceCandidatesBuiltin(t *testing.T) {
	le := binary.LittleEndian
	// One schema item "logo.png", two candidates, and three linked sections.
	schema := make([]byte, 36+78)
	le.PutUint16(schema, 1)
	le.PutUint16(schema[2:], 2)
	le.PutUint16(schema[4:], 2)
	le.PutUint16(schema[28:], 'A')
	le.PutUint16(schema[32:], 'B')
	names := schema[36:]
	le.PutUint32(names[4:], 2)
	le.PutUint32(names[8:], 1)
	le.PutUint32(names[12:], 1)
	le.PutUint32(names[16:], 10)
	le.PutUint32(names[20:], uint32(len(names)))
	names[31] = 0x10 // root scope
	le.PutUint16(names[38:], 8)
	le.PutUint16(names[40:], 'L')
	names[42] = 8
	le.PutUint16(names[44:], 1)
	le.PutUint16(names[56:], 1) // item zero is name node one
	for i, c := range []byte("\x00logo.png\x00") {
		names[58+2*i] = c
	}
	decisions := make([]byte, 24)
	le.PutUint16(decisions[4:], 1) // empty qualifier set
	le.PutUint16(decisions[6:], 1) // decision
	le.PutUint16(decisions[8:], 2) // two references to the same set
	le.PutUint16(decisions[14:], 2)
	resourceMap := make([]byte, 64)
	le.PutUint16(resourceMap[8:], 1)
	le.PutUint16(resourceMap[10:], 1)
	le.PutUint16(resourceMap[12:], 1)
	le.PutUint16(resourceMap[16:], 1)
	le.PutUint32(resourceMap[20:], 2)
	build := func() []byte {
		payloads := [][]byte{schema, decisions, resourceMap}
		tags := []string{"[mrm_hschema]  \x00", "[mrm_decn_info]\x00", "[mrm_res_map2_]\x00"}
		data := make([]byte, 128)
		copy(data, "mrm_pri2")
		le.PutUint32(data[16:], 32)
		le.PutUint32(data[20:], 128)
		le.PutUint16(data[24:], 3)
		for i, p := range payloads {
			size := (32 + len(p) + 8 + 7) &^ 7
			s := make([]byte, size)
			copy(s, tags[i])
			le.PutUint32(s[24:], uint32(size))
			copy(s[32:], p)
			le.PutUint32(s[size-8:], 0xdef5fade)
			le.PutUint32(s[size-4:], uint32(size))
			toc := data[32+32*i:]
			copy(toc, tags[i])
			le.PutUint32(toc[24:], uint32(len(data)-128))
			le.PutUint32(toc[28:], uint32(size))
			data = append(data, s...)
		}
		footer := make([]byte, 16)
		le.PutUint32(footer, 0xdefffade)
		le.PutUint32(footer[4:], uint32(len(data)+16))
		copy(footer[8:], "mrm_pri2")
		data = append(data, footer...)
		le.PutUint32(data[12:], uint32(len(data)))
		return data
	}
	globals := starlark.StringDict{"parse": Builtins()["pri_resource_candidates"], "source": &starfile.Bytes{Data: build()}}
	for expression, want := range map[string]string{"parse(source, 2, [0,0])": "[2, 2]", "parse(source, 2, [])": "[]"} {
		v, err := starlark.Eval(&starlark.Thread{Name: "candidates"}, "test.star", expression, globals)
		if err != nil || v.String() != want {
			t.Fatalf("%s: %v, %v", expression, v, err)
		}
	}
	for _, expression := range []string{"parse(source, 2, [1])", "parse(source, 0, [0])", "parse(source, -1, [0])", "parse(source, 2, [-1])", "parse(source, 2, [0], max_bytes=1)"} {
		if _, err := starlark.Eval(&starlark.Thread{Name: "bad-candidates"}, "test.star", expression, globals); err == nil {
			t.Fatalf("accepted %s", expression)
		}
	}
	// A map may not substitute an unrelated section for its schema/decisions.
	for _, off := range []int{4, 8} {
		original := le.Uint16(resourceMap[off:])
		le.PutUint16(resourceMap[off:], 2)
		globals["source"] = &starfile.Bytes{Data: build()}
		if _, err := starlark.Eval(&starlark.Thread{Name: "bad-link"}, "test.star", "parse(source, 2, [0])", globals); err == nil {
			t.Fatalf("accepted invalid section link at %d", off)
		}
		le.PutUint16(resourceMap[off:], original)
	}
}
