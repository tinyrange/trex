package windows

import (
	"bytes"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestHiveSourceImportPreservesMetadataAndRawValues(t *testing.T) {
	root := newRegistryTree("SOURCE")
	key := ensureRegistryKeyParts(root, []string{"literal/slash", "X:path"})
	key.class = []byte{0, 1, 0xfe, 0xff}
	key.flags, key.flagsSet = 0x20, true
	key.values["X:name"] = registryData{typ: regSZ, data: append(utf16Bytes(`X:\Upper;x:\lower`), 0xff)}
	key.values["binary"] = registryData{typ: regBinary, data: utf16Bytes("X:")}
	key.values["link"] = registryData{typ: regLink, data: utf16Bytes("X:")}
	key.values["unknown"] = registryData{typ: 0x1234, data: []byte{1, 2, 3}}
	key.values["multi"] = registryData{typ: regMultiSZ, data: utf16Bytes("X:\\a\x00x:\\b\x00\x00")}
	ensureRegistryKey(root, "/empty")
	setRegistryValue(root, "/remove/child", "gone", registryString(regSZ, "value"))
	setRegistryValue(root, "/keep", "Drop", registryString(regSZ, "drop"))
	setRegistryValue(root, "/keep/child", "Drop", registryString(regSZ, "keep"))
	data, err := buildRegistryHiveWithFormat(root, registryHiveFormat{major: 1, minor: 3})
	if err != nil {
		t.Fatal(err)
	}
	source := &starfile.Bytes{Name: "source", Data: data}
	// Compare the native import with the original public export/rebuild path.
	legacyPatches, err := hivePatchesBuiltin(nil, nil, starlark.Tuple{source}, []starlark.Tuple{{starlark.String("raw"), starlark.True}})
	if err != nil {
		t.Fatal(err)
	}
	legacyKeys, err := hiveKeysBuiltin(nil, nil, starlark.Tuple{source}, []starlark.Tuple{{starlark.String("metadata"), starlark.True}})
	if err != nil {
		t.Fatal(err)
	}
	old, err := hiveFromPatchesBuiltin(nil, nil, starlark.Tuple{starlark.String("RESULT"), legacyPatches}, []starlark.Tuple{{starlark.String("keys"), legacyKeys}, {starlark.String("format"), source}})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := hiveFromPatchesBuiltin(nil, nil, starlark.Tuple{starlark.String("RESULT"), starlark.NewList(nil)}, []starlark.Tuple{{starlark.String("source"), source}})
	if err != nil {
		t.Fatal(err)
	}
	oldData, _ := starfile.ReadAll(old.(starfile.File))
	freshData, _ := starfile.ReadAll(fresh.(starfile.File))
	if !bytes.Equal(oldData, freshData) {
		t.Fatal("native import differs from lossless export/rebuild")
	}
	drop := starlark.NewDict(2)
	drop.SetKey(starlark.String("key"), starlark.String(`\KEEP`))
	drop.SetKey(starlark.String("name"), starlark.String("drop"))
	result := newRegistryTree("RESULT")
	err = importRegistryHive(result, source, "x:", "C:", starlark.NewList([]starlark.Value{starlark.String("/REMOVE")}), starlark.NewList([]starlark.Value{drop}))
	if err != nil {
		t.Fatal(err)
	}
	target := ensureRegistryKeyParts(result, []string{"literal/slash", "C:path"})
	want := append(utf16Bytes(`C:\Upper;c:\lower`), 0xff)
	if !bytes.Equal(target.values["C:name"].data, want) {
		t.Fatalf("raw UTF16 not relocated losslessly: %x", target.values["C:name"].data)
	}
	if !bytes.Equal(target.values["multi"].data, utf16Bytes("C:\\a\x00c:\\b\x00\x00")) {
		t.Fatal("MULTI_SZ relocation lost separators or terminators")
	}
	for _, name := range []string{"binary", "link"} {
		if !bytes.Equal(target.values[name].data, utf16Bytes("X:")) {
			t.Fatalf("relocated nonstring %s", name)
		}
	}
	if target.values["unknown"].typ != 0x1234 || !bytes.Equal(target.class, key.class) || target.flags != key.flags {
		t.Fatal("lost type or key metadata")
	}
	for name := range result.subkeys {
		if strings.EqualFold(name, "remove") {
			t.Fatal("excluded subtree remains")
		}
	}
	keep := ensureRegistryKey(result, "/keep")
	if len(keep.values) != 0 || len(ensureRegistryKey(result, "/keep/child").values) != 1 {
		t.Fatal("value exclusion was not exact-key/case-insensitive")
	}
	if _, ok := result.subkeys["EMPTY"]; !ok {
		t.Fatal("empty key lost")
	}
	for _, drives := range [][2]string{{"X:", ""}, {"", "C:"}, {"XX:", "C:"}} {
		if importRegistryHive(newRegistryTree("BAD"), source, drives[0], drives[1], starlark.None, starlark.None) == nil {
			t.Fatalf("accepted invalid drives %q", drives)
		}
	}
}
