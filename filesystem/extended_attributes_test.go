package filesystem

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"go.starlark.net/starlark"
	"reflect"
	"testing"
)

func TestDecodeFileFullEACapturedHintAndBounds(t *testing.T) {
	raw, _ := hex.DecodeString("00000000000f0f002443492e436174616c6f6748696e740001000b006e747072696e742e636174")
	eas, err := DecodeFileFullEAInformation(raw)
	want := []ExtendedAttribute{{Name: "$CI.CatalogHint", Value: append([]byte{1, 0, 11, 0}, []byte("ntprint.cat")...)}}
	if err != nil || !reflect.DeepEqual(eas, want) {
		t.Fatalf("%+v: %v", eas, err)
	}
	raw[24] = 9
	if !reflect.DeepEqual(eas, want) {
		t.Fatal("decoder aliases input")
	}
	raw[24] = 1
	for end := 0; end < len(raw); end++ {
		if _, err := DecodeFileFullEAInformation(raw[:end]); err == nil {
			t.Fatalf("accepted truncation %d", end)
		}
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[4] = 1 }, func(b []byte) { b[5] = 255 }, func(b []byte) { b[6] = 255 },
		func(b []byte) { b[23] = 1 }, func(b []byte) { binary.LittleEndian.PutUint32(b, 4) },
		func(b []byte) { binary.LittleEndian.PutUint32(b, 0xfffffffc) },
	} {
		b := bytes.Clone(raw)
		mutate(b)
		if _, err := DecodeFileFullEAInformation(b); err == nil {
			t.Fatalf("accepted malformed %x", b)
		}
	}
	first := append(bytes.Clone(raw), 0)
	binary.LittleEndian.PutUint32(first, 40)
	chain := append(first, []byte{0, 0, 0, 0, 0x80, 1, 1, 0, 'X', 0, 7}...)
	got, err := DecodeFileFullEAInformation(chain)
	if err != nil || len(got) != 2 || got[1].Name != "X" || got[1].Flags != 0x80 || !bytes.Equal(got[1].Value, []byte{7}) {
		t.Fatalf("chain: %+v %v", got, err)
	}
	if _, err := DecodeFileFullEAInformation(append(chain, 0, 0, 0, 0)); err == nil {
		t.Fatal("unbounded terminal padding")
	}
	duplicate := append(first, raw...)
	if _, err := DecodeFileFullEAInformation(duplicate); err == nil {
		t.Fatal("duplicate names")
	}
}

func TestDirectoryEAIdentityIsolationAndPreflight(t *testing.T) {
	d := New()
	d.PutFile("/source", FileRecord{Data: []byte("payload"), Size: 7})
	d.SetMetadata("/source", Metadata{CreationTime: 11, ShortName: "SOURCE~1", FileAttributes: 0x21, HasFileAttributes: true})
	if err := d.HardLink("/source", "/alias"); err != nil {
		t.Fatal(err)
	}
	m := d.metadata["/alias"]
	m.ShortName = "ALIAS~1"
	d.SetMetadata("/alias", m)
	eas := []ExtendedAttribute{{Name: "Existing", Flags: 0x80, Value: []byte{1, 2}}}
	if err := d.SetExtendedAttributes("/alias", eas); err != nil {
		t.Fatal(err)
	}
	eas[0].Value[0] = 99
	snap := d.Snapshot()
	for _, path := range []string{"/source", "/alias"} {
		if snap.Metadata[path].ExtendedAttributes[0].Value[0] != 1 || snap.Metadata[path].CreationTime != 11 || snap.Metadata[path].FileAttributes != 0x21 {
			t.Fatal("EA or unrelated metadata changed")
		}
	}
	if snap.Metadata["/source"].ShortName != "SOURCE~1" || snap.Metadata["/alias"].ShortName != "ALIAS~1" {
		t.Fatal("short names are link-local")
	}
	snap.Metadata["/source"].ExtendedAttributes[0].Value[0] = 88
	if d.metadata["/source"].ExtendedAttributes[0].Value[0] != 1 {
		t.Fatal("snapshot aliases value")
	}
	before := d.Snapshot()
	for _, invalid := range [][]ExtendedAttribute{{{Name: "A"}, {Name: "a"}}, {{Name: "A", Flags: 1}}, {{Name: "A", Value: make([]byte, 65535)}}} {
		if err := d.SetExtendedAttributes("/source", invalid); err == nil || !reflect.DeepEqual(before, d.Snapshot()) {
			t.Fatal("invalid update mutated tree")
		}
	}
	if err := d.SetExtendedAttributes("/missing", nil); err == nil {
		t.Fatal("created missing object")
	}
	value, err := d.getMetadataBuiltin(nil, nil, starlark.Tuple{starlark.String("/source")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := value.(starlark.HasAttrs).Attr("extended_attributes")
	if err != nil {
		t.Fatal(err)
	}
	attrs.(*starlark.List).Index(0).(*starlark.Dict).SetKey(starlark.String("value"), starlark.Bytes("changed"))
	if !reflect.DeepEqual(before, d.Snapshot()) {
		t.Fatal("Starlark view aliases metadata")
	}
	if err := d.SetExtendedAttributes("/source", nil); err != nil || len(d.metadata["/alias"].ExtendedAttributes) != 0 {
		t.Fatal("clear did not follow identity")
	}
}
