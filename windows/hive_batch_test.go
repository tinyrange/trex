package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestHiveBatchPublishedIndexes(t *testing.T) {
	for _, minor := range []uint32{1, 3, 5} {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			root := newRegistryTree("SOFTWARE")
			for i := 0; i < 2200; i++ {
				setRegistryValue(root, fmt.Sprintf("/Wide/Old%04d", i), "keep", registryString(regSZ, "source"))
			}
			source, err := buildRegistryHiveWithFormat(root, registryHiveFormat{major: 1, minor: minor})
			if err != nil {
				t.Fatal(err)
			}
			h := &mutableHive{data: append([]byte(nil), source...), legacyCellPrefix: minor == 1, childBatches: map[uint32]*hiveChildBatch{}}
			for i := 0; i < 2100; i++ {
				path := fmt.Sprintf("/Wide/New%04d/Child", i)
				if err := h.setValue(path, "value", registryString(regSZ, "first")); err != nil {
					t.Fatal(err)
				}
				if err := h.applyValue(path, "VALUE", registryString(regSZ, "second"), 0); err != nil {
					t.Fatal(err)
				}
				if err := h.applyValue(path, "value", registryString(regSZ, ""), infAddRegDeleteValue); err != nil {
					t.Fatal(err)
				}
				if err := h.setValue(path, "final", registryString(regSZ, "final")); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.finishChildBatches(); err != nil {
				t.Fatal(err)
			}
			reopened, err := newRegistryHive(testHiveFile(h.data))
			if err != nil {
				t.Fatal(err)
			}
			wide, err := reopened.lookup("/Wide")
			if err != nil {
				t.Fatal(err)
			}
			children, err := reopened.readSubkeys(wide)
			if err != nil || len(children) != 4300 {
				t.Fatalf("published index %d: %v", len(children), err)
			}
			for _, path := range []string{"/Wide/New0000/Child", "/Wide/New2099/Child", "/Wide/Old2199"} {
				key, err := reopened.lookup(path)
				if err != nil {
					t.Fatal(err)
				}
				values, err := reopened.readRawValues(key)
				if err != nil || len(values) != 1 {
					t.Fatalf("values: %+v %v", values, err)
				}
				security, err := reopened.readKeySecurity(key)
				if err != nil || !bytes.Equal(security, defaultRegistrySecurityDescriptor()) {
					t.Fatalf("security: %v", err)
				}
			}
			// A second transaction must index the newly emitted multi-leaf list.
			h2 := &mutableHive{data: append([]byte(nil), h.data...), legacyCellPrefix: minor == 1, childBatches: map[uint32]*hiveChildBatch{}}
			if err := h2.setValue("/Wide/New0000/Child", "next", registryString(regSZ, "next")); err != nil {
				t.Fatal(err)
			}
			if err := h2.finishChildBatches(); err != nil {
				t.Fatal(err)
			}
			checksum := uint32(0)
			for off := 0; off < 0x1fc; off += 4 {
				checksum ^= binary.LittleEndian.Uint32(h2.data[off:])
			}
			if checksum != binary.LittleEndian.Uint32(h2.data[0x1fc:]) {
				t.Fatal("invalid checksum")
			}
		})
	}
}

func TestHiveBatchCaseFolding(t *testing.T) {
	for _, pair := range [][2]string{{"Kelvin", "Kelvin"}, {"ſtring", "String"}, {"Σ", "ς"}} {
		if foldHiveBatchName(pair[0]) != foldHiveBatchName(pair[1]) {
			t.Fatalf("split fold pair: %q", pair)
		}
	}
	if foldHiveBatchName("ı") == foldHiveBatchName("I") {
		t.Fatal("merged distinct case-fold identities")
	}
}
