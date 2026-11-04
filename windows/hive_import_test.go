package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	registry "github.com/tinyrange/trex/windows/registry"
	"go.starlark.net/starlark"
)

// Read the built hive with the independent portable reader. These paths have
// identical display strings but refer to different physical registry nodes.
func TestHiveImportExclusionsPreserveLiteralComponents(t *testing.T) {
	paths := [][]string{{"C:Literal/Slash", "Leaf"}, {"C:Literal", "Slash", "Leaf"}}
	for _, minor := range []uint32{1, 2, 3, 4, 5} {
		for selected := range paths {
			for _, removeKey := range []bool{false, true} {
				t.Run(fmt.Sprintf("1.%d/path%d/key%t", minor, selected, removeKey), func(t *testing.T) {
					root := newRegistryTree("ROOT")
					for _, parts := range paths {
						node := ensureRegistryKeyParts(root, parts)
						node.flags, node.flagsSet = 0, true
						node.class = utf16Bytes("literal-class")
						node.security = defaultRegistrySecurityDescriptor()
						setRegistryValueParts(root, parts, "C:Value", registryData{typ: 0x1234, data: []byte{0xff, 0, 0x81}})
						setRegistryValueParts(root, parts, "Text", registryString(regSZ, `C:\Windows`))
						ensureRegistryKeyParts(root, appendRegistryPathPart(parts, "Empty"))
					}
					// Backslash, percent and dot spellings in component lists are
					// literal too, not separators, escaping, or path normalization.
					odd := []string{`Literal\Backslash`, "%2f", ".."}
					ensureRegistryKeyParts(root, odd)
					data, err := buildRegistryHiveWithFormat(root, registryHiveFormat{major: 1, minor: minor})
					if err != nil {
						t.Fatal(err)
					}
					parts := append([]string(nil), paths[selected]...)
					parts[0] = "D:" + parts[0][2:]
					// Case-insensitive lookup must not change component boundaries.
					parts[len(parts)-1] = "lEAF"
					record := starlark.NewDict(2)
					if err := record.SetKey(starlark.String("key_parts"), registryPathList(parts)); err != nil {
						t.Fatal(err)
					}
					option := "exclude_keys"
					if !removeKey {
						option = "exclude_values"
						if err := record.SetKey(starlark.String("name"), starlark.String("d:vALUE")); err != nil {
							t.Fatal(err)
						}
					}
					value, err := hiveFromPatchesBuiltin(nil, nil,
						starlark.Tuple{starlark.String("IMPORTED"), starlark.NewList(nil)},
						[]starlark.Tuple{
							{starlark.String("source"), testHiveFile(data)},
							{starlark.String("source_drive"), starlark.String("C:")},
							{starlark.String("target_drive"), starlark.String("D:")},
							{starlark.String(option), starlark.NewList([]starlark.Value{record})},
						})
					if err != nil {
						t.Fatal(err)
					}
					out, err := starfile.ReadAll(value.(starfile.File))
					if err != nil {
						t.Fatal(err)
					}
					if got := binary.LittleEndian.Uint32(out[24:28]); got != minor {
						t.Fatalf("format = %d, want %d", got, minor)
					}
					hive, err := registry.Open(testHiveFile(out))
					if err != nil {
						t.Fatal(err)
					}
					for index, sourceParts := range paths {
						final := append([]string(nil), sourceParts...)
						final[0] = "D:" + final[0][2:]
						key, err := hive.LookupParts(final)
						if removeKey && index == selected {
							if err == nil {
								t.Fatalf("excluded key survived: %q", final)
							}
							if _, err := hive.LookupParts(appendRegistryPathPart(final, "Empty")); err == nil {
								t.Fatal("excluded descendant survived")
							}
							continue
						}
						if err != nil {
							t.Fatal(err)
						}
						class, err := hive.KeyClass(key)
						if err != nil || !bytes.Equal(class, utf16Bytes("literal-class")) || key.Flags != 0 {
							t.Fatalf("metadata changed: %v", err)
						}
						security, err := hive.KeySecurity(key)
						if err != nil || !bytes.Equal(security, defaultRegistrySecurityDescriptor()) {
							t.Fatalf("security changed: %v", err)
						}
						if _, err := hive.LookupParts(appendRegistryPathPart(final, "Empty")); err != nil {
							t.Fatalf("empty key lost: %v", err)
						}
						cells, err := hive.ValueCells(key)
						if err != nil {
							t.Fatal(err)
						}
						wantCount := 2
						if !removeKey && index == selected {
							wantCount = 1
						}
						if len(cells) != wantCount {
							t.Fatalf("value count = %d, want %d at %q", len(cells), wantCount, final)
						}
						for _, cell := range cells {
							v, err := hive.ReadValue(cell)
							if err != nil {
								t.Fatal(err)
							}
							switch v.Name {
							case "D:Value":
								if v.Type != 0x1234 || !bytes.Equal(v.Data, []byte{0xff, 0, 0x81}) {
									t.Fatal("raw value changed")
								}
							case "Text":
								if v.Type != regSZ || !bytes.Equal(v.Data, registryString(regSZ, `D:\Windows`).data) {
									t.Fatal("text relocation changed")
								}
							default:
								t.Fatalf("unexpected value %q", v.Name)
							}
						}
					}
					if _, err := hive.LookupParts(odd); err != nil {
						t.Fatalf("literal backslash/percent/dot key lost: %v", err)
					}
				})
			}
		}
	}
}

func TestHiveImportLegacyExclusionDoesNotMatchLiteralSlash(t *testing.T) {
	root := newRegistryTree("ROOT")
	ensureRegistryKeyParts(root, []string{"Literal/Slash", "Leaf"})
	ensureRegistryKeyParts(root, []string{"Literal", "Slash", "Leaf"})
	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	out := newRegistryTree("IMPORTED")
	if err := importRegistryHive(out, testHiveFile(data), "", "", starlark.NewList([]starlark.Value{starlark.String(`\lITERAL\sLASH`)}), starlark.None); err != nil {
		t.Fatal(err)
	}
	built, err := buildRegistryHive(out)
	if err != nil {
		t.Fatal(err)
	}
	hive, err := registry.Open(testHiveFile(built))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hive.LookupParts([]string{"Literal/Slash", "Leaf"}); err != nil {
		t.Fatalf("literal sibling removed: %v", err)
	}
	if _, err := hive.LookupParts([]string{"Literal", "Slash"}); err == nil {
		t.Fatal("legacy subtree survived")
	}
}
