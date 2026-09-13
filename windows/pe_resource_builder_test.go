package windows

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"go.starlark.net/starlark"
	"testing"
)

func TestPEResourceConstruction(t *testing.T) {
	labels := starlark.NewDict(1)
	_ = labels.SetKey(starlark.String("entry"), starlark.MakeInt(0))
	v, err := pe32ExecutableBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("\x90\xc3"), labels, starlark.NewList(nil)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	source := []byte(v.(starlark.Bytes))
	original := bytes.Clone(source)
	resources := []peResource{
		{typ: "#10", name: "#1", lang: "#1033", data: []byte{17, 0, 17, 0}},
		{typ: "CUSTOM", name: "名", lang: "#0", data: []byte("named")},
		{typ: "#2", name: "#12", lang: "#0", data: []byte("bitmap")},
	}
	out, err := peWithResources(source, resources)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(source, original) {
		t.Fatal("resource construction mutated input")
	}
	parsed, err := peResources(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != len(resources) {
		t.Fatalf("resources: %v", parsed)
	}
	for _, want := range resources {
		found := false
		for _, got := range parsed {
			if got.typ == want.typ && got.name == want.name && got.lang == want.lang {
				found = true
				if !bytes.Equal(got.data, want.data) {
					t.Fatal("resource data changed")
				}
			}
		}
		if !found {
			t.Fatalf("missing %+v", want)
		}
	}
	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	text, err := f.Sections[0].Data()
	if err != nil || !bytes.Equal(text[:2], []byte{0x90, 0xc3}) {
		t.Fatal("code changed")
	}
	stored, computed, err := peChecksums(out)
	if err != nil || stored != computed {
		t.Fatal("invalid resource PE checksum")
	}
	if _, err := peWithResources(source, append(resources, resources[0])); err == nil {
		t.Fatal("duplicate resources accepted")
	}
	// A second transformation must supersede old resources, not retain stale IDs.
	replaced, err := peWithResources(out, resources[:1])
	if err != nil {
		t.Fatal(err)
	}
	got, err := peResources(replaced)
	if err != nil || len(got) != 1 {
		t.Fatal("resource replacement failed")
	}
	broken := bytes.Clone(source)
	peAt := int(binary.LittleEndian.Uint32(broken[60:]))
	binary.LittleEndian.PutUint32(broken[peAt+24+60:], 0)
	if _, err := peWithResources(broken, resources); err == nil {
		t.Fatal("missing section-header capacity accepted")
	}
}
