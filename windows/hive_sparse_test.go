package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/registry"
	"go.starlark.net/starlark"
	"testing"
)

func TestSparseHiveDeletionSecurityAndRecreation(t *testing.T) {
	for _, minor := range []uint32{1, 3, 5} {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			tree := newRegistryTree("ROOT")
			removed := []string{"Literal/Slash", "Old"}
			setRegistryValueParts(tree, removed, "Big", registryData{typ: 3, data: bytes.Repeat([]byte{0x81}, 40000)})
			ensureRegistryKeyParts(tree, appendRegistryPathPart(removed, "Child"))
			keep := ensureRegistryKeyParts(tree, []string{"Keep"})
			keep.class = utf16Bytes("preserve")
			setRegistryValueParts(tree, []string{"Keep"}, "Value", registryString(regSZ, "untouched"))
			data, err := buildRegistryHiveWithFormat(tree, registryHiveFormat{major: 1, minor: minor})
			if err != nil {
				t.Fatal(err)
			}
			source := append([]byte(nil), data...)
			h := &mutableHive{data: data, legacyCellPrefix: minor == 1, childBatches: map[uint32]*hiveChildBatch{}}
			if err := h.deleteKeyParts(removed); err != nil {
				t.Fatal(err)
			}
			replacement, err := h.ensureKeyParts(removed)
			if err != nil {
				t.Fatal(err)
			}
			sd := append([]byte(nil), defaultRegistrySecurityDescriptor()...)
			binary.LittleEndian.PutUint16(sd[2:], binary.LittleEndian.Uint16(sd[2:])|0x1000)
			if err := h.setKeySecurity(replacement, sd); err != nil {
				t.Fatal(err)
			}
			// Share the new security cell, then delete its first owner. The
			// surviving owner must retain a live linked descriptor and count.
			other, err := h.ensureKeyParts([]string{"Other"})
			if err != nil {
				t.Fatal(err)
			}
			if err := h.setKeySecurity(other, sd); err != nil {
				t.Fatal(err)
			}
			if err := h.setValueParts(removed, "Now", registryString(regSZ, "new")); err != nil {
				t.Fatal(err)
			}
			if err := h.finishChildBatches(); err != nil {
				t.Fatal(err)
			}
			h.childBatches = map[uint32]*hiveChildBatch{}
			if err := h.deleteKeyParts([]string{"Other"}); err != nil {
				t.Fatal(err)
			}
			if err := h.finishChildBatches(); err != nil {
				t.Fatal(err)
			}
			r, err := registry.Open(testHiveFile(h.data))
			if err != nil {
				t.Fatal(err)
			}
			counts := map[uint32]uint32{}
			var walk func(registry.Key)
			walk = func(k registry.Key) {
				counts[k.SecurityCell]++
				children, err := r.ReadSubkeys(k)
				if err != nil {
					t.Fatal(err)
				}
				for _, child := range children {
					walk(child)
				}
			}
			root, err := r.ReadKey(r.RootCell())
			if err != nil {
				t.Fatal(err)
			}
			walk(root)
			for cell, want := range counts {
				sk, err := h.securityCell(cell)
				if err != nil || binary.LittleEndian.Uint32(sk[12:]) != want {
					t.Fatalf("security refs: %v, want %d", err, want)
				}
				next, err := h.securityCell(binary.LittleEndian.Uint32(sk[4:]))
				if err != nil || binary.LittleEndian.Uint32(next[8:]) != cell {
					t.Fatal("broken security ring")
				}
			}
			key, err := r.LookupParts(removed)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := r.KeySecurity(key)
			if err != nil || !bytes.Equal(actual, sd) || key.SubkeyCount != 0 || key.ValueCount != 1 {
				t.Fatalf("recreated key: %+v %v", key, err)
			}
			k, err := r.LookupParts([]string{"Keep"})
			if err != nil {
				t.Fatal(err)
			}
			class, err := r.KeyClass(k)
			if err != nil || !bytes.Equal(class, keep.class) {
				t.Fatal("unrelated key class changed")
			}
			old, _ := registry.Open(testHiveFile(source))
			if _, err := old.LookupParts(appendRegistryPathPart(removed, "Child")); err != nil {
				t.Fatal("source snapshot changed")
			}
		})
	}
}

func TestSparseHiveFailureDoesNotMutateSource(t *testing.T) {
	tree := newRegistryTree("ROOT")
	ensureRegistryKey(tree, "/Delete")
	data, err := buildRegistryHiveWithFormat(tree, registryHiveFormat{major: 1, minor: 5})
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), data...)
	_, err = patchHiveBuiltin(nil, nil, starlark.Tuple{testHiveFile(data), starlark.NewList(nil)}, []starlark.Tuple{
		{starlark.String("delete_keys"), starlark.NewList([]starlark.Value{starlark.String("/Delete"), starlark.String("/Missing")})},
	})
	if err == nil || !bytes.Equal(before, data) {
		t.Fatal("failed transaction mutated input or accepted missing deletion")
	}
	// Exercise the exported transaction and independently inspect the output.
	value, err := patchHiveBuiltin(nil, nil, starlark.Tuple{testHiveFile(data), starlark.NewList(nil)}, []starlark.Tuple{
		{starlark.String("delete_keys"), starlark.NewList([]starlark.Value{starlark.String("/Delete")})},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := starfile.ReadAll(value.(starfile.File))
	if err != nil {
		t.Fatal(err)
	}
	r, err := registry.Open(testHiveFile(out))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.LookupParts([]string{"Delete"}); err == nil {
		t.Fatal("deleted key survived")
	}
}
