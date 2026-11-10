package windows

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/registry"
	"go.starlark.net/starlark"
)

func exclusionRecord(parts []string, fields ...starlark.Tuple) *starlark.Dict {
	d := starlark.NewDict(1 + len(fields))
	_ = d.SetKey(starlark.String("key_parts"), registryPathList(parts))
	for _, field := range fields {
		_ = d.SetKey(field[0], field[1])
	}
	return d
}

type exclusionKeyState struct {
	Parts            []string
	Security, Class  []byte
	Flags, NameFlags uint16
	Values           []registry.Value
}

func exclusionContents(t *testing.T, file starfile.File) []exclusionKeyState {
	t.Helper()
	h, err := registry.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	root, err := h.ReadKey(h.RootCell())
	if err != nil {
		t.Fatal(err)
	}
	var result []exclusionKeyState
	var walk func(registry.Key, []string)
	walk = func(k registry.Key, parts []string) {
		security, err := h.KeySecurity(k)
		if err != nil {
			t.Fatal(err)
		}
		class, err := h.KeyClass(k)
		if err != nil {
			t.Fatal(err)
		}
		entry := exclusionKeyState{Parts: parts, Security: security, Class: class, Flags: k.Flags, NameFlags: k.NameFlags}
		cells, err := h.ValueCells(k)
		if err != nil {
			t.Fatal(err)
		}
		for _, cell := range cells {
			v, err := h.ReadValue(cell)
			if err != nil {
				t.Fatal(err)
			}
			entry.Values = append(entry.Values, v)
		}
		result = append(result, entry)
		children, err := h.ReadSubkeys(k)
		if err != nil {
			t.Fatal(err)
		}
		for _, child := range children {
			walk(child, appendRegistryPathPart(parts, child.Name))
		}
	}
	walk(root, nil)
	return result
}

// Compare to the existing full importer, not another sparse implementation.
// Descendant-first input, case duplicates and missing paths all describe one
// epoch. A retired parent must never expose old child/value state on recreation.
func TestSparseHiveExclusionsMatchImport(t *testing.T) {
	for _, minor := range []uint32{1, 2, 3, 4, 5} {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			tree := newRegistryTree("ROOT")
			for _, parts := range [][]string{{"Retire", "Child"}, {"Retire", "Sibling"}, {"Literal/Slash"}, {"Literal", "Slash"}, {"Keep"}} {
				node := ensureRegistryKeyParts(tree, parts)
				node.class = utf16Bytes("class")
				setRegistryValueParts(tree, parts, "Big", registryData{typ: 3, data: bytes.Repeat([]byte{0x83}, 40000)})
				setRegistryValueParts(tree, parts, "", registryString(regSZ, "default"))
				setRegistryValueParts(tree, parts, "Keep", registryString(regSZ, "keep"))
			}
			data, err := buildRegistryHiveWithFormat(tree, registryHiveFormat{major: 1, minor: minor})
			if err != nil {
				t.Fatal(err)
			}
			before := append([]byte(nil), data...)
			source := testHiveFile(data)
			keys := starlark.NewList([]starlark.Value{
				exclusionRecord([]string{"Retire", "Child"}), exclusionRecord([]string{"retire"}),
				exclusionRecord([]string{"RETIRE"}), exclusionRecord([]string{"Missing", "Child"}),
				exclusionRecord([]string{"Literal/Slash"}),
			})
			values := starlark.NewList([]starlark.Value{
				exclusionRecord([]string{"Keep"}, starlark.Tuple{starlark.String("name"), starlark.String("bIG")}),
				exclusionRecord([]string{"Keep"}, starlark.Tuple{starlark.String("name"), starlark.String("(default)")}),
				exclusionRecord([]string{"Keep"}, starlark.Tuple{starlark.String("name"), starlark.String("Missing")}),
				exclusionRecord([]string{"Retire", "Child"}, starlark.Tuple{starlark.String("name"), starlark.String("Big")}),
				exclusionRecord([]string{"Missing"}, starlark.Tuple{starlark.String("name"), starlark.String("Big")}),
			})
			sd := defaultRegistrySecurityDescriptor()
			recreated := starlark.NewList([]starlark.Value{exclusionRecord([]string{"Retire"}, starlark.Tuple{starlark.String("security"), starlark.Bytes(sd)})})
			patch := exclusionRecord([]string{"Retire"}, starlark.Tuple{starlark.String("name"), starlark.String("New")}, starlark.Tuple{starlark.String("type"), starlark.MakeInt(3)}, starlark.Tuple{starlark.String("value"), starlark.Bytes("new")})
			patches := starlark.NewList([]starlark.Value{patch})
			options := []starlark.Tuple{{starlark.String("exclude_keys"), keys}, {starlark.String("exclude_values"), values}, {starlark.String("keys"), recreated}}
			sparse, err := patchHiveBuiltin(nil, nil, starlark.Tuple{source, patches}, options)
			if err != nil {
				t.Fatal(err)
			}
			imported, err := hiveFromPatchesBuiltin(nil, nil, starlark.Tuple{starlark.String("ROOT"), patches}, append(options, starlark.Tuple{starlark.String("source"), source}))
			if err != nil {
				t.Fatal(err)
			}
			got, want := exclusionContents(t, sparse.(starfile.File)), exclusionContents(t, imported.(starfile.File))
			if !reflect.DeepEqual(got, want) {
				if len(got) != len(want) {
					t.Fatalf("key count %d != %d", len(got), len(want))
				}
				for i := range got {
					if !reflect.DeepEqual(got[i], want[i]) {
						t.Fatalf("key %q differs: flags %x/%x vs %x/%x, security %t class %t values %d/%d", got[i].Parts, got[i].Flags, got[i].NameFlags, want[i].Flags, want[i].NameFlags, bytes.Equal(got[i].Security, want[i].Security), bytes.Equal(got[i].Class, want[i].Class), len(got[i].Values), len(want[i].Values))
					}
				}
			}
			if !bytes.Equal(data, before) {
				t.Fatal("source modified")
			}
			old, _ := registry.Open(source)
			now, _ := registry.Open(sparse.(starfile.File))
			a, _ := old.LookupParts([]string{"Literal", "Slash"})
			b, _ := now.LookupParts([]string{"Literal", "Slash"})
			if a != b {
				t.Fatal("unrelated key metadata or location changed")
			}
		})
	}
}

func TestSparseHiveExclusionFailuresArePrivate(t *testing.T) {
	tree := newRegistryTree("ROOT")
	ensureRegistryKey(tree, "/Retire/Child")
	data, err := buildRegistryHive(tree)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), data...)
	remove := starlark.NewList([]starlark.Value{starlark.String("/Retire")})
	for name, options := range map[string][]starlark.Tuple{
		"root":          {{starlark.String("exclude_keys"), starlark.NewList([]starlark.Value{starlark.String("/")})}},
		"mixed":         {{starlark.String("exclude_keys"), remove}, {starlark.String("delete_keys"), remove}},
		"late-security": {{starlark.String("exclude_keys"), remove}, {starlark.String("keys"), starlark.NewList([]starlark.Value{exclusionRecord([]string{"Retire"}, starlark.Tuple{starlark.String("security"), starlark.Bytes("bad")})})}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := patchHiveBuiltin(nil, nil, starlark.Tuple{testHiveFile(data), starlark.NewList(nil)}, options)
			if err == nil {
				t.Fatal("accepted invalid transaction")
			}
			if !bytes.Equal(data, before) {
				t.Fatal("failed transaction modified source")
			}
		})
	}
}
