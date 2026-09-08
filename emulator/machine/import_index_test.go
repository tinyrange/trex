package machine

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/tinyrange/trex/emulator/amd64"
	"github.com/tinyrange/trex/emulator/cpu"
	"go.starlark.net/starlark"
)

// Export registration should not scale with the number of unrelated imports.
func BenchmarkProvideExportIndexed(b *testing.B) {
	for _, count := range []int{0, 1000, 10000} {
		b.Run(fmt.Sprintf("imports%d", count), func(b *testing.B) {
			m := &Machine{hooks: make(map[uint64]hook)}
			for i := 0; i < count; i++ {
				m.addImport(imported{module: "other.dll", name: fmt.Sprintf("Function%d", i), address: uint64(i)})
			}
			callback := starlark.NewBuiltin("run", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
				return starlark.None, nil
			})
			args := starlark.Tuple{callback}
			kwargs := []starlark.Tuple{{starlark.String("module"), starlark.String("support.dll")}, {starlark.String("name"), starlark.String("Run")}}
			thread := &starlark.Thread{}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := m.environmentMethod(thread, "provide_export", args, kwargs); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestProvidedExportUpdatesIndexedIATs(t *testing.T) {
	const base = 0x200000000
	m := &Machine{processor: &amd64.CPU{}, memory: cpu.NewAddressSpace(4096), hooks: make(map[uint64]hook), nextAllocation: base + 1024}
	if err := m.memory.Map(base, make([]byte, 128), cpu.Read|cpu.Write); err != nil {
		t.Fatal(err)
	}
	items := []imported{
		{module: "SUPPORT.DLL", name: "Run", iat: base, address: 1},
		{module: "support.dll", name: "rUN", iat: base + 8, address: 2},
		{module: "support.dll", ordinal: 7, iat: base + 16, address: 3},
		{module: "other.dll", name: "Run", iat: base + 24, address: 4},
	}
	for _, item := range items {
		m.addImport(item)
	}
	callback := starlark.NewBuiltin("run", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return starlark.MakeInt(7), nil
	})
	provide := func(machine *Machine, module, name string, ordinal int) uint64 {
		t.Helper()
		kwargs := []starlark.Tuple{{starlark.String("module"), starlark.String(module)}, {starlark.String("name"), starlark.String(name)}, {starlark.String("ordinal"), starlark.MakeInt(ordinal)}}
		value, err := machine.environmentMethod(&starlark.Thread{}, "provide_export", starlark.Tuple{callback}, kwargs)
		if err != nil {
			t.Fatal(err)
		}
		address, err := unsigned(value)
		if err != nil {
			t.Fatal(err)
		}
		return address
	}
	check := func(machine *Machine, offset, want uint64) {
		t.Helper()
		var data [8]byte
		if err := machine.memory.ReadMemory(base+offset, data[:], cpu.Read); err != nil {
			t.Fatal(err)
		}
		if got := binary.LittleEndian.Uint64(data[:]); got != want {
			t.Fatalf("IAT +%d = %#x, want %#x", offset, got, want)
		}
	}
	address := provide(m, `C:\Windows\System32\Support`, "RUN", 0)
	check(m, 0, address)
	check(m, 8, address)
	check(m, 16, 0)
	check(m, 24, 0)
	ordinalAddress := provide(m, "support", "", 7)
	check(m, 16, ordinalAddress)
	if ordinalAddress == address {
		t.Fatal("named and ordinal exports collided")
	}

	// Later module imports must enter the index, and re-provisioning must
	// update every matching slot while preserving the export's address.
	clone := m.clone()
	clone.addImport(imported{module: "support.dll", name: "Run", iat: base + 32, address: 5})
	if got := provide(clone, "SUPPORT", "run", 0); got != address {
		t.Fatal("re-provision changed address")
	}
	check(clone, 32, address)
	check(m, 32, 0)
	if got := provide(m, "support", "Run", 0); got != address {
		t.Fatal("original export changed address")
	}
	check(m, 32, 0)

	// The clone must own bucket storage, not just a copied map header.
	key := exportKey("support", "run", 0)
	clone.importIATs[key][0] = base + 40
	if m.importIATs[key][0] != base {
		t.Fatal("snapshot aliases index bucket")
	}
	if len(m.importIATs[key]) != 2 || len(clone.importIATs[key]) != 3 {
		t.Fatal("snapshot aliases index membership")
	}
}
