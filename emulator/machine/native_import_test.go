package machine

import (
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/emulator/amd64"
	"github.com/tinyrange/trex/emulator/cpu"
	"go.starlark.net/starlark"
)

func TestNativeDataImportBinding(t *testing.T) {
	const iat = 0x200000000
	m := &Machine{processor: &amd64.CPU{}, memory: cpu.NewAddressSpace(1 << 20), memoryLimit: 1 << 20}
	if err := m.memory.Map(iat, make([]byte, 32), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	m.addImport(imported{module: "data.dll", name: "Object", iat: iat, address: 0x7fff00000000})
	m.addImport(imported{module: "data.dll", ordinal: 1, iat: iat + 8, address: 0x7fff00000010})
	data := relocatableFixture(t, true)
	put := func(offset int, value uint32) { binary.LittleEndian.PutUint32(data[offset:], value) }
	put(0x98+112, 0x11a0)
	put(0x98+116, 0x50)
	put(0x3ac, 0x11d2)
	put(0x3b0, 1)
	put(0x3b4, 1)
	put(0x3b8, 1)
	put(0x3bc, 0x11c8)
	put(0x3c0, 0x11cc)
	put(0x3c4, 0x11d0)
	put(0x3c8, 0x1080)
	put(0x3cc, 0x11e0)
	copy(data[0x3d2:], "data.dll\x00")
	copy(data[0x3e0:], "Object\x00")
	loaded, err := m.load(data, "data.dll")
	if err != nil {
		t.Fatal(err)
	}
	read := func(address uint64) uint64 {
		t.Helper()
		var value [8]byte
		if err := m.memory.ReadMemory(address, value[:], cpu.Read); err != nil {
			t.Fatal(err)
		}
		return binary.LittleEndian.Uint64(value[:])
	}
	for _, address := range []uint64{iat, iat + 8} {
		if got := read(address); got != loaded.image.Base+0x1080 || read(got) != loaded.image.Base+0x1000 {
			t.Fatalf("native data import at %#x = %#x", address, got)
		}
	}
	callback := starlark.NewBuiltin("override", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return starlark.MakeInt(0), nil
	})
	hookMethod, _ := m.Attr("hook")
	if _, err := starlark.Call(&starlark.Thread{}, hookMethod, starlark.Tuple{callback}, []starlark.Tuple{{starlark.String("address"), starlark.MakeUint64(0x7fff00000000)}}); err != nil {
		t.Fatal(err)
	}
	if err := m.relinkImports(); err != nil {
		t.Fatal(err)
	}
	if read(iat) != 0x7fff00000000 || read(iat+8) != loaded.image.Base+0x1080 {
		t.Fatal("native relinking lost explicit import hook or changed sibling slot")
	}
}

func TestProvidedExportKeepsBindingAfterImportHook(t *testing.T) {
	const iat, thunk, provided = uint64(0x2000), uint64(0x7fff00000000), uint64(0x7ffe00000000)
	m := &Machine{memory: cpu.NewAddressSpace(1 << 20), provided: map[string]uint64{exportKey("test.dll", "Function", 0): provided}}
	if err := m.memory.Map(iat, make([]byte, 8), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	item := imported{module: "test.dll", name: "Function", iat: iat, address: thunk}
	m.addImport(item)
	if err := m.writeImportAddress(iat, provided); err != nil {
		t.Fatal(err)
	}
	m.setHook(thunk, hook{})
	if err := m.bindImportHook(item, thunk); err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		var data [8]byte
		if err := m.memory.ReadMemory(iat, data[:], cpu.Read); err != nil {
			t.Fatal(err)
		}
		if got := binary.LittleEndian.Uint64(data[:]); got != provided {
			t.Fatalf("IAT = %#x, want provided export %#x", got, provided)
		}
	}
	check()
	if err := m.relinkImports(); err != nil {
		t.Fatal(err)
	}
	check()
}
