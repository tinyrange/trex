package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"go.starlark.net/starlark"
	"strings"
	"testing"

	registry "github.com/tinyrange/trex/windows/registry"
)

func TestRegistryPortableAndStarlarkReaderParity(t *testing.T) {
	for _, minor := range []uint32{1, 2, 3, 4, 5, 6} {
		t.Run(fmt.Sprintf("1.%d", minor), func(t *testing.T) {
			root := newRegistryTree("ROOT")
			parts := []string{"literal/slash", `literal\backslash`, "UnicodeΩ"}
			key := ensureRegistryKeyParts(root, parts)
			key.flags, key.flagsSet = 0, true
			key.class = utf16Bytes("class-data")
			key.security = defaultRegistrySecurityDescriptor()
			want := bytes.Repeat([]byte{0x71}, hiveBigDataSegmentSize+19)
			setRegistryValueParts(root, parts, "Large", registryData{typ: regBinary, data: want})
			setRegistryValueParts(root, parts, "", registryDWORD(17))
			data, err := buildRegistryHiveWithFormat(root, registryHiveFormat{major: 1, minor: minor})
			if err != nil {
				t.Fatal(err)
			}
			portable, err := registry.Open(testHiveFile(data))
			if err != nil {
				t.Fatal(err)
			}
			scripting, err := newRegistryHive(testHiveFile(data))
			if err != nil {
				t.Fatal(err)
			}
			pk, err := portable.LookupParts(parts)
			if err != nil {
				t.Fatal(err)
			}
			sk, err := scripting.lookupParts(parts)
			if err != nil {
				t.Fatal(err)
			}
			if portableKey(sk) != pk || pk.Flags != 0 {
				t.Fatalf("key metadata differs: %+v %+v", pk, sk)
			}
			pc, err := portable.KeyClass(pk)
			if err != nil {
				t.Fatal(err)
			}
			sc, err := scripting.readKeyClass(sk)
			if err != nil || !bytes.Equal(pc, key.class) || !bytes.Equal(pc, sc) {
				t.Fatalf("class mismatch: %x %x %v", pc, sc, err)
			}
			ps, err := portable.KeySecurity(pk)
			if err != nil {
				t.Fatal(err)
			}
			ss, err := scripting.readKeySecurity(sk)
			if err != nil || !bytes.Equal(ps, key.security) || !bytes.Equal(ps, ss) {
				t.Fatalf("security mismatch: %v", err)
			}
			cells, err := portable.ValueCells(pk)
			if err != nil {
				t.Fatal(err)
			}
			for _, cell := range cells {
				pv, err := portable.ReadValue(cell)
				if err != nil {
					t.Fatal(err)
				}
				sv, err := scripting.readValue(cell)
				if err != nil {
					t.Fatal(err)
				}
				name := pv.Name
				if name == "" {
					name = "(default)"
				}
				if sv.name != name || sv.typ != pv.Type || !bytes.Equal(sv.raw, pv.Data) {
					t.Fatalf("value %q differs", name)
				}
				if name == "Large" && !bytes.Equal(pv.Data, want) {
					t.Fatal("large value differs")
				}
			}
		})
	}
}

func TestBothRegistryReadersRejectCyclicSubkeyIndex(t *testing.T) {
	root := newRegistryTree("ROOT")
	ensureRegistryKey(root, "/Child")
	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	portable, err := registry.Open(testHiveFile(data))
	if err != nil {
		t.Fatal(err)
	}
	key, err := portable.ReadKey(portable.RootCell())
	if err != nil {
		t.Fatal(err)
	}
	offset := hiveBaseBlockSize + int(key.SubkeyList) + 4
	copy(data[offset:], "ri")
	binary.LittleEndian.PutUint16(data[offset+2:], 1)
	binary.LittleEndian.PutUint32(data[offset+4:], key.SubkeyList)
	if _, err := portable.ReadSubkeys(key); err == nil || !strings.Contains(err.Error(), "cyclic") {
		t.Fatalf("portable: %v", err)
	}
	scripting, err := newRegistryHive(testHiveFile(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scripting.readSubkeys(scriptingKey(key)); err == nil || !strings.Contains(err.Error(), "cyclic") {
		t.Fatalf("Starlark: %v", err)
	}
}

func TestRegistryWholeTreeExportsRejectKeyCycles(t *testing.T) {
	root := newRegistryTree("ROOT")
	setRegistryValue(root, "/Child", "Value", registryDWORD(1))
	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := HiveEntries(testHiveFile(data))
	if err != nil || len(entries) != 3 {
		t.Fatalf("valid entries=%+v err=%v", entries, err)
	}
	hive, err := newRegistryHive(testHiveFile(data))
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := hive.lookup("/")
	if err != nil {
		t.Fatal(err)
	}
	child, err := hive.lookup("/Child")
	if err != nil {
		t.Fatal(err)
	}
	offset := hiveBaseBlockSize + int(child.cell) + 4
	binary.LittleEndian.PutUint32(data[offset+0x14:], 1)
	binary.LittleEndian.PutUint32(data[offset+0x1c:], rootKey.subkeyList) // child now points to itself
	checks := []func() error{
		func() error { _, err := HiveEntries(testHiveFile(data)); return err },
		func() error { _, err := HiveJSON(testHiveFile(data), 10000); return err },
		func() error { return hive.appendKeys(rootKey, nil, starlark.NewList(nil)) },
		func() error { return hive.appendKeyMetadata(rootKey, nil, starlark.NewList(nil)) },
		func() error { return hive.appendPatches(rootKey, nil, starlark.NewList(nil)) },
		func() error { return hive.appendRawPatches(rootKey, nil, starlark.NewList(nil)) },
	}
	for index, check := range checks {
		if err := check(); err == nil || !strings.Contains(err.Error(), "cyclic") {
			t.Fatalf("export %d: %v", index, err)
		}
	}
}
