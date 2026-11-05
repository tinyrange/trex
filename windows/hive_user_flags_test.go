package windows

import (
	"bytes"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/registry"
	"go.starlark.net/starlark"
	"testing"
)

func userFlagRecord(parts []string, flags starlark.Value) *starlark.Dict {
	d := starlark.NewDict(2)
	_ = d.SetKey(starlark.String("key_parts"), registryPathList(parts))
	if flags != nil {
		_ = d.SetKey(starlark.String("user_flags"), flags)
	}
	return d
}

func TestHiveUserFlagsPreservedAcrossEditsAndImport(t *testing.T) {
	root := newRegistryTree("ROOT")
	parts := []string{"Literal/Slash"}
	parent := ensureRegistryKeyParts(root, parts)
	parent.nameFlags = 0xace3 // Exercise user flags AND unrelated high bits.
	ensureRegistryKeyParts(root, []string{"Literal/Slash", "long child"})
	ensureRegistryKeyParts(root, []string{"Literal/Slash", "x"})
	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	source := append([]byte(nil), data...)
	result, err := patchHiveBuiltin(nil, nil, starlark.Tuple{testHiveFile(data), starlark.NewList(nil)}, []starlark.Tuple{
		{starlark.String("delete_keys"), starlark.NewList([]starlark.Value{userFlagRecord([]string{"Literal/Slash", "long child"}, nil)})},
		{starlark.String("key_flags"), starlark.NewList([]starlark.Value{userFlagRecord(parts, starlark.MakeInt(10))})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, source) {
		t.Fatal("source changed")
	}
	check := func(v starlark.Value, wantNameLen uint16) {
		t.Helper()
		reader, err := registry.Open(v.(starfile.File))
		if err != nil {
			t.Fatal(err)
		}
		key, err := reader.LookupParts(parts)
		if err != nil {
			t.Fatal(err)
		}
		if key.NameFlags != 0xacea {
			t.Fatalf("packed flags = %#x", key.NameFlags)
		}
		body, err := reader.ReadCell(key.Cell)
		if err != nil {
			t.Fatal(err)
		}
		if n := binary.LittleEndian.Uint16(body[0x34:]); n != wantNameLen {
			t.Fatalf("maximum name length = %d, want %d", n, wantNameLen)
		}
		hive, err := newRegistryHive(v.(starfile.File))
		if err != nil {
			t.Fatal(err)
		}
		k, err := hive.lookupParts(parts)
		if err != nil {
			t.Fatal(err)
		}
		attribute, err := (&registryKey{hive: hive, key: k, parts: parts}).Attr("user_flags")
		if err != nil || attribute.String() != "10" {
			t.Fatalf("attribute %v: %v", attribute, err)
		}
	}
	check(result, 2)
	// A longer sibling must update the low half without treating packed flags
	// as an enormous maximum, and without resetting those flags.
	grown, err := patchHiveBuiltin(nil, nil, starlark.Tuple{result, starlark.NewList(nil)}, []starlark.Tuple{
		{starlark.String("keys"), starlark.NewList([]starlark.Value{userFlagRecord([]string{"Literal/Slash", "new longer child"}, nil)})},
	})
	if err != nil {
		t.Fatal(err)
	}
	check(grown, 32)
	imported, err := hiveFromPatchesBuiltin(nil, nil, starlark.Tuple{starlark.String("COPY"), starlark.NewList(nil)}, []starlark.Tuple{{starlark.String("source"), grown}})
	if err != nil {
		t.Fatal(err)
	}
	check(imported, 32)
}

func TestHiveUserFlagsStrictAndAtomic(t *testing.T) {
	root := newRegistryTree("ROOT")
	ensureRegistryKeyParts(root, []string{"Existing"}).nameFlags = 0x5ab4
	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), data...)
	cases := []starlark.Value{starlark.MakeInt(-1), starlark.MakeInt(16), starlark.String("2"), starlark.True, nil}
	for _, flags := range cases {
		_, err := patchHiveBuiltin(nil, nil, starlark.Tuple{testHiveFile(data), starlark.NewList(nil)}, []starlark.Tuple{{starlark.String("key_flags"), starlark.NewList([]starlark.Value{
			userFlagRecord([]string{"Existing"}, starlark.MakeInt(1)), userFlagRecord([]string{"Existing"}, flags),
		})}})
		if err == nil {
			t.Fatalf("accepted %v", flags)
		}
		if !bytes.Equal(data, before) {
			t.Fatal("failed edit changed source")
		}
	}
	_, err = patchHiveBuiltin(nil, nil, starlark.Tuple{testHiveFile(data), starlark.NewList(nil)}, []starlark.Tuple{{starlark.String("key_flags"), starlark.NewList([]starlark.Value{userFlagRecord([]string{"Missing"}, starlark.MakeInt(2))})}})
	if err == nil {
		t.Fatal("flag edit created absent key")
	}
	if !bytes.Equal(data, before) {
		t.Fatal("missing-key failure changed source")
	}
}

func TestHiveVirtualizationFlagsDoNotClobberUserOrMetadata(t *testing.T) {
	for _, flags := range []int{0, 1, 2, 4, 8, 10, 15} {
		root := newRegistryTree("ROOT")
		key := ensureRegistryKeyParts(root, []string{"Key"})
		key.flags, key.flagsSet = 0xa0, true
		key.nameFlags = 0xf5c7
		data, err := buildRegistryHive(root)
		if err != nil {
			t.Fatal(err)
		}
		source := append([]byte(nil), data...)
		rec := userFlagRecord([]string{"Key"}, nil)
		_ = rec.SetKey(starlark.String("virtualization_flags"), starlark.MakeInt(flags))
		result, err := patchHiveBuiltin(nil, nil, starlark.Tuple{testHiveFile(data), starlark.NewList(nil)}, []starlark.Tuple{{starlark.String("key_flags"), starlark.NewList([]starlark.Value{rec})}})
		if err != nil {
			t.Fatal(err)
		}
		h, err := registry.Open(result.(starfile.File))
		if err != nil {
			t.Fatal(err)
		}
		k, err := h.LookupParts([]string{"Key"})
		if err != nil {
			t.Fatal(err)
		}
		wantNK := uint16(0xa0)
		if flags&2 != 0 {
			wantNK = 0x20
		}
		if k.NameFlags != 0xf507|uint16(flags)<<4 || k.Flags != wantNK {
			t.Fatalf("flags %d: packed=%#x NK=%#x", flags, k.NameFlags, k.Flags)
		}
		if !bytes.Equal(source, data) {
			t.Fatal("source changed")
		}
	}
}
