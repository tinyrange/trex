package windows

import (
	"bytes"
	"encoding/binary"
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestWMIClassDecoderAndBounds(t *testing.T) {
	d, err := parseMOF(`class Sample { [key] string Name; boolean Enabled = TRUE; uint32 Count=7; string Tags[] = {"one","two"}; };`)
	if err != nil {
		t.Fatal(err)
	}
	c := d.Classes[0]
	raw, err := buildWMIClassRecord(c, nil, c.Features, 0, 123, wmiObjectContext{})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeWMIClassRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.class.Name != "Sample" || decoded.revision != 123 || len(decoded.properties) != 4 || !hasMOFQualifier(decoded.properties[0].feature.Qualifiers, "key") {
		t.Fatalf("decoded: %#v", decoded)
	}
	// Truncation before the complete class part may never panic or succeed.
	classEnd := 12 + int(binary.LittleEndian.Uint32(raw[12:]))
	for n := 0; n < classEnd; n++ {
		if _, err := decodeWMIClassRecord(raw[:n]); err == nil {
			t.Fatalf("accepted truncated class at %d", n)
		}
	}
	bad := bytes.Clone(raw)
	binary.LittleEndian.PutUint32(bad, 0xffffffff)
	if _, err := decodeWMIClassRecord(bad); err == nil {
		t.Fatal("accepted overflowing superclass size")
	}
}
func TestWMISHA256InstanceIdentity(t *testing.T) {
	d, err := parseMOF(`class Item { [key] string Name; }; instance of Item {Name="example";};`)
	if err != nil {
		t.Fatal(err)
	}
	raw, key, err := buildWMIInstanceRecordWithHash(wmiUpperUTF16SHA256, d.Instances[0], d.Classes[0], d.Classes[0].Features, 12, 11, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := wmiDecodeUTF16(raw[:128])
	if err != nil {
		t.Fatal(err)
	}
	if hash != wmiUpperUTF16SHA256("Item") || len(key) != 64 || key != wmiUpperUTF16SHA256("example") {
		t.Fatalf("hash=%s key=%s", hash, key)
	}
	if binary.LittleEndian.Uint64(raw[128:]) != 12 || !strings.EqualFold(d.Classes[0].Name, "Item") {
		t.Fatal("wrong modern instance header")
	}
}
func TestWMIModernSampledPageChecksum(t *testing.T) {
	// Independent standard vector, distributed at the observed sector stride.
	page := make([]byte, wmiRepositoryPageSize)
	copyVector := []byte("123456789abcdefg")
	for i, b := range copyVector {
		page[i*512] = b
	}
	// Check against bit-at-a-time IEEE polynomial, not the table implementation.
	crc := uint32(0xffffffff)
	for _, b := range copyVector {
		crc ^= uint32(b)
		for bit := 0; bit < 8; bit++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xedb88320
			} else {
				crc >>= 1
			}
		}
	}
	want := ^crc
	if got := wmiModernPageCRC(page); got != want {
		t.Fatalf("crc %x != %x", got, want)
	}
	page[1] ^= 0xff
	if wmiModernPageCRC(page) != want {
		t.Fatal("unsampled byte affected page checksum")
	}
	page[512] ^= 0xff
	if wmiModernPageCRC(page) == want {
		t.Fatal("sampled byte did not affect page checksum")
	}
}

func TestWMILegacyClassAndInstanceInspection(t *testing.T) {
	doc, err := parseMOF(`
class Parent {[key] string Name; boolean Enabled=TRUE;};
[provider("Example")] class Child : Parent { uint32 Count; };
instance of Child { Name="sample"; Count=42; };
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{doc}, `root\cimv2`)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := repository.classLayout(`root\cimv2`, "Child")
	if err != nil {
		t.Fatal(err)
	}
	if len(layout.properties) != 3 || layout.declaring[0] != "Parent" || layout.declaring[2] != "Child" {
		t.Fatalf("lost inheritance: %#v", layout)
	}
	instances, err := repository.instancesBuiltin(nil, nil, starlark.Tuple{starlark.String(`root\cimv2`), starlark.String("Child")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	list := instances.(*starlark.List)
	if list.Len() != 1 {
		t.Fatalf("legacy instances: %v", list)
	}
	record := list.Index(0).(starlark.HasAttrs)
	value, _ := record.Attr("properties")
	properties := value.(*starlark.Dict)
	for name, want := range map[string]starlark.Value{"Name": starlark.String("sample"), "Enabled": starlark.True, "Count": starlark.MakeInt(42)} {
		got, found, err := properties.Get(starlark.String(name))
		if err == nil && found {
			got, err = got.(starlark.HasAttrs).Attr("value")
		}
		if err != nil || !found || got.String() != want.String() {
			t.Fatalf("property %s: %v %v", name, got, err)
		}
	}
	for _, rec := range repository.records {
		if len(rec.data) > 64 {
			if _, err := decodeWMIInstanceWithHash(rec.data, layout, wmiUpperUTF16SHA256); err == nil {
				t.Fatal("legacy record accepted with SHA-256 instance identity")
			}
		}
	}
}
