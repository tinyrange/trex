package windows

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestRegistryChildrenNamesAndValues(t *testing.T) {
	keys := starlark.NewDict(0)
	for _, key := range []string{"SYSTEM\x00/parent", "SYSTEM\x00/parent/child/grandchild", "SYSTEM\x00/parent/a%2fb", "SYSTEM\x00/parent/%252f", "SYSTEM\x00/parentsibling/wrong", "SOFTWARE\x00/parent/wrong"} {
		_ = keys.SetKey(starlark.String(key), starlark.True)
	}
	result, err := registryChildrenBuiltin(nil, nil, starlark.Tuple{keys, starlark.String("system"), starlark.String("\\PARENT\\")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := result.(*starlark.Dict)
	if names.Len() != 3 {
		t.Fatalf("names = %s", names)
	}
	for _, name := range []string{"child", "a/b", "%2f"} {
		v, found, _ := names.Get(starlark.String(name))
		if !found || v != starlark.String(name) {
			t.Fatalf("missing name %q", name)
		}
	}
	values := starlark.NewDict(0)
	for _, key := range []string{"SYSTEM\x00/parent\x00(default)", "SYSTEM\x00/parent\x00a/b", "SYSTEM\x00/parent/child\x00wrong", "SYSTEM\x00/parentsibling\x00wrong", "SYSTEM\x00/\x00root"} {
		_ = values.SetKey(starlark.String(key), starlark.String(key))
	}
	for _, tc := range []struct {
		key   string
		count int
	}{{"/parent", 2}, {"/", 1}, {"/absent", 0}} {
		result, err := registryChildrenBuiltin(nil, nil, starlark.Tuple{values, starlark.String("system"), starlark.String(tc.key)}, []starlark.Tuple{{starlark.String("values"), starlark.True}})
		if err != nil {
			t.Fatal(err)
		}
		if result.(*starlark.Dict).Len() != tc.count {
			t.Fatalf("%s: %s", tc.key, result)
		}
	}
}

func TestRegistryPartitionBoundariesAndOwnership(t *testing.T) {
	for _, values := range []bool{false, true} {
		entries := starlark.NewDict(5)
		identities := []string{"SYSTEM\x00/parent", "SYSTEM\x00/parentsibling", "SYSTEM\x00/parent/child", "SOFTWARE\x00/parent", "SYSTEM\x00/"}
		for _, identity := range identities {
			if values {
				identity += "\x00value"
			}
			_ = entries.SetKey(starlark.String(identity), starlark.String(identity))
		}
		for _, tc := range []struct {
			key   string
			count int
		}{{"\\PaReNt\\", 2}, {"/", 4}, {"/missing", 0}} {
			result, err := registryPartitionBuiltin(nil, nil, starlark.Tuple{entries, starlark.String("system"), starlark.String(tc.key)}, []starlark.Tuple{{starlark.String("values"), starlark.Bool(values)}})
			if err != nil {
				t.Fatal(err)
			}
			parts := result.(starlark.Tuple)
			selected, remaining := parts[0].(*starlark.Dict), parts[1].(*starlark.Dict)
			if selected.Len() != tc.count || remaining.Len() != 5-tc.count {
				t.Fatalf("%q values=%v: %s", tc.key, values, result)
			}
			for _, part := range []*starlark.Dict{selected, remaining} {
				previous := -1
				for _, key := range part.Keys() {
					position := -1
					for i, original := range entries.Keys() {
						if key == original {
							position = i
						}
					}
					if position <= previous {
						t.Fatal("partition changed input order")
					}
					previous = position
				}
			}
			_ = selected.SetKey(starlark.String("extra"), starlark.None)
			if entries.Len() != 5 {
				t.Fatal("partition mutated source")
			}
		}
	}
}
