package windows

import (
	"bytes"
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func definitionFixture() []byte {
	// Original delta VDM header, with a bounded synthetic payload. The native
	// observed generation FILETIME is independently recorded below.
	data := make([]byte, 125)
	copy(data, "RMDX")
	binary.LittleEndian.PutUint32(data[4:8], 1758074921)
	binary.LittleEndian.PutUint32(data[8:12], 0xffffffff)
	binary.LittleEndian.PutUint32(data[12:16], 0x00200002)
	binary.LittleEndian.PutUint32(data[24:28], 124)
	binary.LittleEndian.PutUint32(data[28:32], 32286)
	return data
}

func TestDefenderDefinitionSourceDate(t *testing.T) {
	labels := starlark.NewDict(1)
	_ = labels.SetKey(starlark.String("entry"), starlark.MakeInt(0))
	image, err := pe32ExecutableBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("\xc3"), labels, starlark.NewList(nil)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := peWithResources([]byte(image.(starlark.Bytes)), []peResource{{typ: "RT_RCDATA", name: "#1000", lang: "#1033", data: definitionFixture()}})
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(data)
	object := &windowsPE{file: &starfile.Bytes{Data: data}, cache: make(starlark.StringDict)}
	value, err := object.Attr("defender_definition")
	if err != nil {
		t.Fatal(err)
	}
	got, _, _ := value.(*starlark.Dict).Get(starlark.String("created_filetime"))
	if got.String() != "134025485210000000" {
		t.Fatalf("source date = %v", got)
	}
	if !bytes.Equal(data, before) {
		t.Fatal("metadata read mutated the source")
	}
	if err := value.(*starlark.Dict).SetKey(starlark.String("created_unix"), starlark.MakeInt(0)); err == nil {
		t.Fatal("metadata must be immutable")
	}
}

func TestDefenderDefinitionRejectsUnknownAndAmbiguousHeaders(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"empty", func(b []byte) []byte { return nil }},
		{"truncated", func(b []byte) []byte { return b[:31] }},
		{"magic", func(b []byte) []byte { b[0] = 0; return b }},
		{"unknown_layout", func(b []byte) []byte { b[12] = 3; return b }},
		{"unknown_checksum", func(b []byte) []byte { b[8] = 0; return b }},
		{"unknown_reserved", func(b []byte) []byte { b[16] = 1; return b }},
		{"zero_date", func(b []byte) []byte { clear(b[4:8]); return b }},
		{"empty_payload", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[24:28], 125); return b }},
		{"offset_overflow", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[24:28], 0xffffffff); return b }},
		{"zero_output", func(b []byte) []byte { clear(b[28:32]); return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := defenderDefinitionMetadata([]peResource{{typ: "#10", name: "#1000", data: tc.mutate(definitionFixture())}}); err == nil {
				t.Fatal("accepted malformed metadata")
			}
		})
	}
	resources := []peResource{{typ: "RT_RCDATA", name: "#1000", lang: "#1033", data: definitionFixture()}, {typ: "#10", name: "#1000", lang: "#0", data: definitionFixture()}}
	if _, err := defenderDefinitionMetadata(resources); err == nil {
		t.Fatal("accepted ambiguous language resources")
	}
	v, err := defenderDefinitionMetadata([]peResource{{typ: "#10", name: "#999", data: definitionFixture()}})
	if err != nil || v != starlark.None {
		t.Fatalf("unrelated resource: %v %v", v, err)
	}
}
