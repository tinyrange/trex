package windows

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func modernTestSeed(t *testing.T, text string) *wmiRepositoryFile {
	t.Helper()
	d, err := parseMOF(text)
	if err != nil {
		t.Fatal(err)
	}
	seed := &wmiRepositoryFile{
		modern: &wmiModernMapping{objects: wmiModernSection{generation: 100, first: 12, second: 11}, index: wmiModernSection{generation: 100, first: 12, second: 11}},
		files:  starlark.StringDict{"OBJECTS.DATA": &starfile.Bytes{Name: "OBJECTS.DATA"}},
	}
	r, err := seed.appendDocuments([]*mofDocument{d}, `root\cimv2`, "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestWMIModernAppendPreservesBaseAndImportsLayout(t *testing.T) {
	base := modernTestSeed(t, `class Base { [key] string Name; uint32 Count=17; }; instance of Base {Name="old";};`)
	before, err := readWMIRepositoryFile(base.files["OBJECTS.DATA"].(starfile.File), "OBJECTS.DATA")
	if err != nil {
		t.Fatal(err)
	}
	// A second document refers to a class absent from its source. Its instance
	// must use the imported property order, key qualifier, default and revision.
	d, err := parseMOF(`instance of Base {Name="new";};`)
	if err != nil {
		t.Fatal(err)
	}
	after, err := base.appendDocuments([]*mofDocument{d}, `root\cimv2`, "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := readWMIRepositoryFile(after.files["OBJECTS.DATA"].(starfile.File), "OBJECTS.DATA")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, before) || len(after.records) != len(base.records)+1 {
		t.Fatal("base store or record count changed")
	}
	keys := map[string]bool{}
	for _, page := range after.pages {
		for _, k := range page.keys {
			keys[k] = true
		}
	}
	for _, page := range base.pages {
		for _, k := range page.keys {
			if !keys[k] {
				t.Fatalf("lost %s", k)
			}
		}
	}
	layout, err := after.classLayout(`root\cimv2`, "Base")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, rec := range after.records {
		if len(rec.data) < 128 {
			continue
		}
		hash, err := wmiDecodeUTF16(rec.data[:128])
		if err != nil || hash != wmiUpperUTF16SHA256("Base") {
			continue
		}
		v, err := decodeWMIModernInstance(rec.data, layout)
		if err != nil {
			t.Fatal(err)
		}
		if v["Count"].Integer != 17 {
			t.Fatalf("lost imported default: %#v", v)
		}
		found[v["Name"].Text] = true
	}
	if !found["old"] || !found["new"] || len(found) != 2 {
		t.Fatalf("instances: %v", found)
	}
	if _, err := after.appendDocuments([]*mofDocument{d}, `root\cimv2`, ""); err == nil || !strings.Contains(err.Error(), "replace existing key") {
		t.Fatalf("duplicate append: %v", err)
	}
	// Both older checkpoints must independently reference valid new stores, not
	// the old index. Select each older checkpoint by giving it a later generation.
	files := starlark.NewDict(5)
	for name, value := range after.files {
		files.SetKey(starlark.String(name), value)
	}
	for i, name := range []string{"MAPPING2.MAP", "MAPPING1.MAP"} {
		raw, err := readWMIRepositoryFile(after.files[name].(starfile.File), name)
		if err != nil {
			t.Fatal(err)
		}
		mapping, err := parseWMIModernMapping(raw)
		if err != nil {
			t.Fatal(err)
		}
		mapping.objects.generation = after.modern.objects.generation + uint32(i) + 1
		mapping.index.generation = mapping.objects.generation
		files.SetKey(starlark.String(name), &starfile.Bytes{Name: name, Data: serializeWMIModernMapping(mapping)})
		fallback, err := readWMIModernRepository(files)
		if err != nil {
			t.Fatal(err)
		}
		if len(fallback.records) != len(after.records) {
			t.Fatal("fallback lost records")
		}
	}
}

func TestWMIModernInheritedQualifierOverride(t *testing.T) {
	r := modernTestSeed(t, `class Parent { [Read] string Name; }; class Child : Parent { [Key] string Name; };`)
	changed := false
	for i := range r.records {
		raw := r.records[i].data
		decoded, err := decodeWMIClassRecord(raw)
		if err != nil || decoded.class.Name != "Child" {
			continue
		}
		// Model the inherited descriptor emitted by modern WMI: the child adds
		// Key but still obtains the property type and Read qualifier from its parent.
		name := []byte{0, 'N', 'a', 'm', 'e', 0}
		pos := bytes.Index(raw, name) + len(name)
		if pos < len(name) || binary.LittleEndian.Uint32(raw[pos:]) != 8 {
			t.Fatal("fixture descriptor missing")
		}
		binary.LittleEndian.PutUint32(raw[pos:], 0x4008)
		changed = true
	}
	if !changed {
		t.Fatal("child fixture missing")
	}
	layout, err := r.classLayout(`root\cimv2`, "Child")
	if err != nil {
		t.Fatal(err)
	}
	p := layout.properties[0]
	if !hasMOFQualifier(p.feature.Qualifiers, "Read") || !hasMOFQualifier(p.feature.Qualifiers, "Key") || p.feature.Type.Name != "string" || layout.declaring[0] != "Parent" {
		t.Fatalf("lost inherited metadata or child key: %#v", p.feature)
	}
}
