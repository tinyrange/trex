package uefi

import (
	"bytes"
	"context"
	"debug/pe"
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"io"
	"testing"
)

func fixture(t *testing.T, code ...uint32) *io.SectionReader {
	t.Helper()
	data := make([]byte, 0x400)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	var h bytes.Buffer
	h.WriteString("PE\x00\x00")
	o := pe.OptionalHeader64{Magic: 0x20b, ImageBase: ramBase + 0x10000, AddressOfEntryPoint: 0x1000, SizeOfImage: 0x2000, SizeOfHeaders: 0x200, SectionAlignment: 0x1000, FileAlignment: 0x200, NumberOfRvaAndSizes: 16, Subsystem: 10}
	for _, v := range []any{pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_ARM64, NumberOfSections: 1, SizeOfOptionalHeader: uint16(binary.Size(o)), Characteristics: pe.IMAGE_FILE_EXECUTABLE_IMAGE}, o, pe.SectionHeader32{Name: [8]byte{'.', 't', 'e', 'x', 't'}, VirtualAddress: 0x1000, VirtualSize: uint32(len(code) * 4), PointerToRawData: 0x200, SizeOfRawData: 0x200, Characteristics: 0x60000020}} {
		if err := binary.Write(&h, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	copy(data[0x80:], h.Bytes())
	for j, v := range code {
		binary.LittleEndian.PutUint32(data[0x200+j*4:], v)
	}
	return io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data)))
}

func TestCheckpointRestoresCPUFirmwareAndMemory(t *testing.T) {
	m := machine(t, 0x14000000)
	saved, err := m.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	key := m.mapKey
	p := m.allocate(0, 4, 1, 0)
	m.u64(p, 123)
	m.processor.SetRegister("x7", 456)
	m.SetVariable(Variable{Name: "Example", GUID: loadedImageGUID, Attributes: 7, Data: []byte{1}})
	if err := m.Restore(saved); err != nil {
		t.Fatal(err)
	}
	if m.mapKey != key || m.read64(p) != 0 || len(m.variables) != 0 {
		t.Fatal("firmware/RAM not restored")
	}
	r, _ := m.Register("x7")
	if r != 0 {
		t.Fatal("register not restored")
	}
	m.u64(p, 789)
	if err := m.Restore(saved); err != nil {
		t.Fatal(err)
	}
	if m.read64(p) != 0 {
		t.Fatal("checkpoint mutated after restore")
	}
	other := machine(t, 0x14000000)
	if err := other.Restore(saved); err == nil {
		t.Fatal("foreign checkpoint accepted")
	}
}

func TestStopsTraceAndWatchAreResumable(t *testing.T) {
	m := machine(t, 0xf9000020, 0x14000000) // STR X0,[X1]; B .
	m.SetRegister("x1", ramBase+0x200000)
	m.SetRegister("x0", 42)
	pc, _ := m.Register("pc")
	r := m.RunWithOptions(context.Background(), RunOptions{Steps: 10, StopPCs: []uint64{pc}})
	if r.Reason != "address_stop" || r.Steps != 0 {
		t.Fatalf("%+v", r)
	}
	r = m.RunWithOptions(context.Background(), RunOptions{Steps: 10, Watches: []Watch{{ramBase + 0x200000, 8, cpu.Write}}})
	if r.Reason != "memory_watch" || r.Steps != 1 || m.read64(ramBase+0x200000) != 42 {
		t.Fatalf("%+v", r)
	}
	r = m.RunWithOptions(context.Background(), RunOptions{Steps: 10, TraceLimit: 3})
	if r.Reason != "budget" || r.Steps != 11 || len(r.Trace) != 3 {
		t.Fatalf("%+v", r)
	}
	for _, address := range r.Trace {
		if address != pc+4 {
			t.Fatal("trace is not last N")
		}
	}
	gate := m.gate("ExitBootServices")
	m.SetRegister("pc", gate)
	r = m.RunWithOptions(context.Background(), RunOptions{Steps: 1, StopServices: []string{"ExitBootServices"}})
	if r.Reason != "service_stop" || m.exited {
		t.Fatal("service stop dispatched")
	}
}

func TestSampleEventsPreserveExecution(t *testing.T) {
	m := machine(t, 0x91000400, 0x17ffffff) // ADD X0,X0,#1; B back
	entry := m.processor.PC()
	before, _ := m.Register("x0")
	var pcs []uint64
	m.opts.Observe = func(e Event) error {
		if e.Kind == "sample" {
			pcs = append(pcs, e.PC)
		}
		return nil
	}
	r := m.RunWithOptions(context.Background(), RunOptions{Steps: 10, SampleInterval: 3})
	after, _ := m.Register("x0")
	if r.Reason != "budget" || r.Steps != 10 || after != before+5 || len(pcs) != 4 {
		t.Fatalf("result=%+v x0=%d samples=%x", r, after, pcs)
	}
	for j, pc := range pcs {
		if pc != entry+uint64(j%2)*4 {
			t.Fatalf("sample %d = %#x", j, pc)
		}
	}
}

func TestEventKindsFilterAndCheckpoint(t *testing.T) {
	m := machine(t, 0x14000000)
	var kinds []string
	m.opts.Observe = func(e Event) error { kinds = append(kinds, e.Kind); return nil }
	for _, test := range []struct {
		filter []string
		want   int
	}{
		{nil, 3}, {[]string{}, 0}, {[]string{"console"}, 1},
	} {
		m.opts.EventKinds = test.filter
		checkpoint, err := m.Checkpoint()
		if err != nil {
			t.Fatal(err)
		}
		m.opts.EventKinds = nil
		if err = m.Restore(checkpoint); err != nil {
			t.Fatal(err)
		}
		kinds = nil
		for _, kind := range []string{"service", "console", "accelerator"} {
			m.emit(Event{Kind: kind})
		}
		if len(kinds) != test.want {
			t.Fatalf("filter=%v events=%v", test.filter, kinds)
		}
	}
}
func machine(t *testing.T, code ...uint32) *Machine {
	t.Helper()
	m, err := New(fixture(t, code...), Options{Memory: 16 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEFIImageRunsToValidatedExitBootServices(t *testing.T) {
	m := machine(t,
		0xaa0003f4, // MOV X20,X0 (image handle)
		0xf9403033, // LDR X19,[X1,#96] (boot services)
		0xd14007ff, // SUB SP,SP,#4096
		0xd2820008, // MOV X8,#4096
		0xf90003e8, // STR X8,[SP] (map capacity)
		0x910003e0, 0x910103e1, 0x910023e2, 0x910043e3, 0x910063e4,
		0xf9401e68, 0xd63f0100, // GetMemoryMap
		0xf94007e1, 0xaa1403e0, 0xf9407668, 0xd63f0100, // ExitBootServices(image,key)
	)
	r := m.Run(context.Background(), 1000)
	if r.Reason != "exit_boot_services" {
		t.Fatalf("%+v", r)
	}
	if r.Steps != 18 || r.MapKey != 3 {
		t.Fatalf("%+v", r)
	}
	if m.args()[0] != 0 || m.processor.PC() == 0 {
		t.Fatal("missing successful return context")
	}
}

func TestMemoryMapKeyInvalidatedByAllocationAndFree(t *testing.T) {
	m := machine(t, 0xd65f03c0)
	key := m.mapKey
	p := m.allocate(0, 4, 1, 0)
	if p == 0 || key == m.mapKey {
		t.Fatal("allocation did not update map")
	}
	if status, ok := m.dispatch("ExitBootServices", [8]uint64{m.imageHandle, key}); !ok || status != invalidParameter || m.exited {
		t.Fatal("accepted stale key")
	}
	key = m.mapKey
	if !m.free(p, 1) || key == m.mapKey {
		t.Fatal("free did not update map")
	}
	if status, _ := m.dispatch("ExitBootServices", [8]uint64{m.imageHandle, m.mapKey}); status != 0 || !m.exited {
		t.Fatal("rejected current key")
	}
}

func TestStopBudgetAndUnsupportedServicePreserveContext(t *testing.T) {
	m := machine(t, 0x14000000)
	r := m.Run(context.Background(), 7)
	if r.Reason != "budget" || r.Steps != 7 {
		t.Fatalf("%+v", r)
	}
	m.processor.SetPC(m.gate("Unknown"))
	pc := m.processor.PC()
	r = m.Run(context.Background(), 1)
	if r.Reason != "unsupported_service" || r.PC != pc || r.Steps != 7 {
		t.Fatalf("%+v", r)
	}
}

func TestMemoryMapCoversRAMWithoutOverlap(t *testing.T) {
	m := machine(t, 0xd65f03c0)
	m.allocate(2, 2, 1, ramBase+0x200000)
	b := m.descriptors()
	end := m.ramBase
	for j := 0; j < len(b); j += 40 {
		base := binary.LittleEndian.Uint64(b[j+8:])
		pages := binary.LittleEndian.Uint64(b[j+24:])
		if base != end || pages == 0 {
			t.Fatal("gap/overlap")
		}
		end = base + pages*page
	}
	if end != ramBase+m.opts.Memory {
		t.Fatal("incomplete map")
	}
}
