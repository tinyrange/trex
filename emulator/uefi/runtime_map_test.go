package uefi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

const runtimeTestBase = uint64(0x10000)
const runtimeTestVirtual = uint64(0xffff800000000000)

func runtimeTestRAM() []byte {
	ram := make([]byte, 64<<10)
	for i := range ram {
		ram[i] = byte(i*31 + 7)
	}
	for offset := 24; offset < 136; offset += 8 {
		binary.LittleEndian.PutUint64(ram[0x500+offset:], runtimeTestBase+0x1000+uint64(offset))
	}
	for offset, pointer := range map[int]uint64{24: runtimeTestBase + 0x800, 88: runtimeTestBase + 0x500, 112: runtimeTestBase + 0x2000} {
		binary.LittleEndian.PutUint64(ram[0x100+offset:], pointer)
	}
	return ram
}

func runtimeTestDescriptor(physical, virtual, pages uint64) []byte {
	data := make([]byte, 40)
	binary.LittleEndian.PutUint32(data, 6)
	binary.LittleEndian.PutUint64(data[8:], physical)
	binary.LittleEndian.PutUint64(data[16:], virtual)
	binary.LittleEndian.PutUint64(data[24:], pages)
	binary.LittleEndian.PutUint64(data[32:], 1<<63|8)
	return data
}

func TestRuntimeMapAdapterParity(t *testing.T) {
	for _, variant := range []struct {
		name   string
		status uint64
	}{
		{"valid", 0},
		{"padded descriptors", 0},
		{"UINT32 version", 0},
		{"physical overlap", invalidParameter},
		{"virtual overlap", invalidParameter},
		{"physical overflow", invalidParameter},
		{"virtual overflow", invalidParameter},
		{"zero pages", invalidParameter},
		{"misalignment", invalidParameter},
		{"invalid stride", invalidParameter},
		{"invalid version", invalidParameter},
		{"before ExitBootServices", invalidParameter},
		{"missing system pointer", notFound},
		{"unmapped system table", invalidParameter},
		{"repeat", invalidParameter},
	} {
		t.Run(variant.name, func(t *testing.T) {
			var previous []byte
			for _, adapter := range []string{"caller", "native"} {
				t.Run(adapter, func(t *testing.T) {
					ram := runtimeTestRAM()
					descriptor := runtimeTestDescriptor(runtimeTestBase, runtimeTestVirtual, 16)
					args := [4]uint64{40, 40, 1, runtimeTestBase + 0x8000}
					m := &Machine{ramBase: runtimeTestBase, systemTable: runtimeTestBase + 0x100, exited: true, opts: Options{Memory: uint64(len(ram))}}
					switch variant.name {
					case "padded descriptors":
						descriptor = append(descriptor, make([]byte, 8)...)
						args[0], args[1] = 48, 48
					case "UINT32 version":
						args[2] = 0xfeedbeef00000001
					case "physical overlap":
						descriptor = append(descriptor, runtimeTestDescriptor(runtimeTestBase+4096, runtimeTestVirtual+0x20000, 1)...)
						args[0] = 80
					case "virtual overlap":
						descriptor = append(descriptor, runtimeTestDescriptor(runtimeTestBase+0x10000, runtimeTestVirtual+4096, 1)...)
						args[0] = 80
					case "physical overflow":
						binary.LittleEndian.PutUint64(descriptor[8:], ^uint64(4095))
					case "virtual overflow":
						binary.LittleEndian.PutUint64(descriptor[16:], ^uint64(4095))
					case "zero pages":
						binary.LittleEndian.PutUint64(descriptor[24:], 0)
					case "misalignment":
						binary.LittleEndian.PutUint64(descriptor[16:], runtimeTestVirtual+1)
					case "invalid stride":
						args[1] = 39
					case "invalid version":
						args[2] = 2
					case "before ExitBootServices":
						m.exited = false
					case "missing system pointer":
						// Runtime service pointers fit; the system table's last
						// pointer does not, after preparing all runtime changes.
						binary.LittleEndian.PutUint64(descriptor[24:], 2)
					case "unmapped system table":
						m.systemTable = runtimeTestBase + uint64(len(ram)) - 16
					}
					copy(ram[0x8000:], descriptor)
					var memory cpu.Memory
					var mapping *runtimeMap
					var call func() (uint64, error)
					if adapter == "caller" {
						space := cpu.NewAddressSpace(uint64(len(ram)))
						if err := space.Map(runtimeTestBase, ram, cpu.Read|cpu.Write); err != nil {
							t.Fatal(err)
						}
						memory = space
						f := &Firmware{machine: m, physical: space}
						mapping = &f.virtualMap
						call = func() (uint64, error) {
							var a [10]uint64
							copy(a[:], args[:])
							return f.setVirtualAddressMap(a)
						}
					} else {
						n := &NativeExecution{base: runtimeTestBase, ram: ram, firmware: m}
						memory, mapping = n, &n.virtualMap
						call = func() (uint64, error) {
							var a [8]uint64
							copy(a[:], args[:])
							status := n.setVirtualAddressMap(a)
							return status, m.err
						}
					}
					m.firmwareMemory = memory
					before := bytes.Clone(ram)
					if variant.name == "repeat" {
						if status, err := call(); status != 0 || err != nil {
							t.Fatalf("first call: %#x, %v", status, err)
						}
						if err := memory.ReadMemory(runtimeTestBase, before, cpu.Read); err != nil {
							t.Fatal(err)
						}
					}
					status, err := call()
					if status != variant.status || err != nil && variant.name != "unmapped system table" {
						t.Fatalf("map status=%#x err=%v, want %#x", status, err, variant.status)
					}
					after := make([]byte, len(ram))
					if err := memory.ReadMemory(runtimeTestBase, after, cpu.Read); err != nil {
						t.Fatal(err)
					}
					if status != 0 {
						if !bytes.Equal(before, after) {
							t.Fatal("rejected map changed guest memory")
						}
						if variant.name != "repeat" && *mapping != nil {
							t.Fatal("rejected map was committed")
						}
					} else {
						for offset := 24; offset < 136; offset += 8 {
							if got, want := binary.LittleEndian.Uint64(after[0x500+offset:]), runtimeTestVirtual+0x1000+uint64(offset); got != want {
								t.Fatalf("runtime pointer at %d=%#x, want %#x", offset, got, want)
							}
						}
						for offset, want := range map[int]uint64{24: runtimeTestVirtual + 0x800, 88: runtimeTestVirtual + 0x500, 112: runtimeTestVirtual + 0x2000} {
							if got := binary.LittleEndian.Uint64(after[0x100+offset:]); got != want {
								t.Fatalf("system pointer at %d=%#x, want %#x", offset, got, want)
							}
						}
						for _, table := range [][]byte{after[0x100 : 0x100+120], after[0x500 : 0x500+136]} {
							copy := bytes.Clone(table)
							want := binary.LittleEndian.Uint32(copy[16:])
							clear(copy[16:20])
							if crc32.ChecksumIEEE(copy) != want {
								t.Fatal("relocated table checksum")
							}
						}
						// Bytes outside the two tables must survive the single
						// atomic span write, including the boot services table.
						preserved := bytes.Clone(after)
						copy(preserved[0x100:0x100+120], before[0x100:0x100+120])
						copy(preserved[0x500:0x500+136], before[0x500:0x500+136])
						if !bytes.Equal(preserved, before) {
							t.Fatal("relocation changed bytes outside the tables")
						}
					}
					if previous != nil && !bytes.Equal(previous, after) {
						t.Fatal("adapters produced different memory")
					}
					previous = after
				})
			}
		})
	}
}

type rejectingRuntimeMemory struct {
	cpu.Memory
	failCheck bool
	writes    int
	err       error
}

func (m *rejectingRuntimeMemory) CheckMemory(address uint64, size int, access cpu.Access) error {
	if m.failCheck && access&cpu.Write != 0 {
		return m.err
	}
	return m.Memory.CheckMemory(address, size, access)
}

func (m *rejectingRuntimeMemory) WriteMemory(uint64, []byte) error {
	m.writes++
	return m.err
}

func TestRuntimeMapWriteRejectionIsAtomic(t *testing.T) {
	for _, failCheck := range []bool{false, true} {
		ram := runtimeTestRAM()
		copy(ram[0x8000:], runtimeTestDescriptor(runtimeTestBase, runtimeTestVirtual, 16))
		space := cpu.NewAddressSpace(uint64(len(ram)))
		if err := space.Map(runtimeTestBase, ram, cpu.Read|cpu.Write); err != nil {
			t.Fatal(err)
		}
		injected := errors.New("injected write failure")
		physical := &rejectingRuntimeMemory{Memory: space, failCheck: failCheck, err: injected}
		m := &Machine{ramBase: runtimeTestBase, systemTable: runtimeTestBase + 0x100, exited: true, opts: Options{Memory: uint64(len(ram))}, firmwareMemory: space}
		f := &Firmware{machine: m, physical: physical}
		status, err := f.setVirtualAddressMap([10]uint64{40, 40, 1, runtimeTestBase + 0x8000})
		if status != invalidParameter || !errors.Is(err, injected) || f.virtualMap != nil {
			t.Fatalf("write failure: status=%#x err=%v map=%v", status, err, f.virtualMap)
		}
		after := make([]byte, len(ram))
		if err := space.ReadMemory(runtimeTestBase, after, cpu.Read); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ram, after) {
			t.Fatal("write rejection changed memory")
		}
		wantWrites := 1
		if failCheck {
			wantWrites = 0
		}
		if physical.writes != wantWrites {
			t.Fatalf("writes=%d, want %d", physical.writes, wantWrites)
		}
	}
}
