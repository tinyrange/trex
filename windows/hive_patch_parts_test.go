package windows

import (
	"bytes"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/registry"
	"go.starlark.net/starlark"
	"testing"
)

func TestPatchHiveLiteralParts(t *testing.T) {
	for _, minor := range []uint32{1, 3, 5} {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			paths := [][]string{{"A/B", "..", "Leaf"}, {"A", "B", "..", "Leaf"}}
			root := newRegistryTree("SOFTWARE")
			for _, parts := range paths {
				setRegistryValueParts(root, parts, "value", registryString(regSZ, "before"))
				node := ensureRegistryKeyParts(root, parts)
				node.class = utf16Bytes("class")
				node.security = defaultRegistrySecurityDescriptor()
			}
			data, err := buildRegistryHiveWithFormat(root, registryHiveFormat{major: 1, minor: minor})
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(data)
			patch := func(parts []string, name, value string, del bool) *starlark.Dict {
				d := starlark.NewDict(5)
				d.SetKey(starlark.String("key_parts"), registryPathList(parts))
				d.SetKey(starlark.String("name"), starlark.String(name))
				d.SetKey(starlark.String("type"), starlark.String("REG_SZ"))
				d.SetKey(starlark.String("value"), starlark.String(value))
				d.SetKey(starlark.String("delete"), starlark.Bool(del))
				return d
			}
			added := []string{"A/B", "..", "New/Leaf"}
			patches := starlark.NewList([]starlark.Value{patch(paths[0], "value", "", true), patch(paths[0], "value", "after", false), patch(added, "new", "created", false)})
			result, err := patchHiveBuiltin(nil, nil, starlark.Tuple{testHiveFile(data), patches}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(original, data) {
				t.Fatal("source modified")
			}
			file := result.(starfile.File)
			h, err := registry.Open(file)
			if err != nil {
				t.Fatal(err)
			}
			for i, parts := range paths {
				k, err := h.LookupParts(parts)
				if err != nil {
					t.Fatal(err)
				}
				cells, err := h.ValueCells(k)
				if err != nil {
					t.Fatal(err)
				}
				want := "before"
				if i == 0 {
					want = "after"
				}
				if len(cells) != 1 {
					t.Fatalf("%v: value count %d", parts, len(cells))
				}
				value, err := h.ReadValue(cells[0])
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(value.Data, utf16Bytes(want+"\x00")) {
					t.Fatalf("%v: %+v", parts, value)
				}
				class, err := h.KeyClass(k)
				if err != nil || !bytes.Equal(class, utf16Bytes("class")) {
					t.Fatal("class metadata changed", err)
				}
				security, err := h.KeySecurity(k)
				if err != nil || !bytes.Equal(security, defaultRegistrySecurityDescriptor()) {
					t.Fatal("security changed", err)
				}
			}
			if _, err := h.LookupParts(added); err != nil {
				t.Fatal(err)
			}
			if _, err := h.LookupParts([]string{"A/B", "..", "New", "Leaf"}); err == nil {
				t.Fatal("literal slash became a separator")
			}
		})
	}
}
