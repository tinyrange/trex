package starlarkfrontend

import (
	"encoding/binary"
	"fmt"
	"sort"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type workflowObject struct {
	typeName string
	attrs    starlark.StringDict
	ready    <-chan struct{}
}

func (v *workflowObject) String() string        { return "<" + v.typeName + ">" }
func (v *workflowObject) Type() string          { return v.typeName }
func (v *workflowObject) Freeze()               {}
func (v *workflowObject) Truth() starlark.Bool  { return starlark.True }
func (v *workflowObject) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", v.typeName) }
func (v *workflowObject) Attr(name string) (starlark.Value, error) {
	return v.attrs[name], nil
}
func (v *workflowObject) AttrNames() []string {
	names := make([]string, 0, len(v.attrs))
	for name := range v.attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
func (v *workflowObject) DebugReady() <-chan struct{} { return v.ready }

type workflowGDB struct {
	value       *workflowObject
	memory      []byte
	registers   map[string]uint64
	stops       []starlark.Value
	points      []*workflowPoint
	continues   int
	steps       int
	interrupts  int
	restoreSeen bool
}

type workflowPoint struct {
	value   *workflowObject
	address uint64
	size    uint64
	kind    string
	removed bool
}

func newWorkflowPoint(address, size uint64, kind string) *workflowPoint {
	point := &workflowPoint{address: address, size: size, kind: kind}
	point.value = &workflowObject{typeName: "fake_point", attrs: starlark.StringDict{
		"address": starlark.MakeUint64(address),
		"remove": workflowBuiltin("remove", func(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			point.removed = true
			return starlark.None, nil
		}),
	}}
	return point
}

func (p *workflowPoint) String() string        { return p.value.String() }
func (p *workflowPoint) Type() string          { return p.value.Type() }
func (p *workflowPoint) Freeze()               {}
func (p *workflowPoint) Truth() starlark.Bool  { return starlark.True }
func (p *workflowPoint) Hash() (uint32, error) { return p.value.Hash() }
func (p *workflowPoint) Attr(name string) (starlark.Value, error) {
	return p.value.Attr(name)
}
func (p *workflowPoint) AttrNames() []string { return p.value.AttrNames() }

func newWorkflowGDB(memorySize int) *workflowGDB {
	gdb := &workflowGDB{memory: make([]byte, memorySize), registers: map[string]uint64{"cr3": 0x111000}}
	ready := make(chan struct{})
	gdb.value = &workflowObject{typeName: "fake_gdb", ready: ready, attrs: starlark.StringDict{}}
	gdb.value.attrs["architecture"] = starlark.String("i386")
	gdb.value.attrs["read_memory"] = workflowBuiltin("read_memory", gdb.readMemory)
	gdb.value.attrs["write_memory"] = workflowBuiltin("write_memory", gdb.writeMemory)
	gdb.value.attrs["search_memory"] = workflowBuiltin("search_memory", gdb.searchMemory)
	gdb.value.attrs["registers"] = workflowBuiltin("registers", gdb.readRegisters)
	gdb.value.attrs["write_register"] = workflowBuiltin("write_register", gdb.writeRegister)
	gdb.value.attrs["breakpoint"] = workflowBuiltin("breakpoint", gdb.breakpoint)
	gdb.value.attrs["watchpoint"] = workflowBuiltin("watchpoint", gdb.watchpoint)
	gdb.value.attrs["continue"] = workflowBuiltin("continue", gdb.resume)
	gdb.value.attrs["step"] = workflowBuiltin("step", gdb.step)
	gdb.value.attrs["interrupt"] = workflowBuiltin("interrupt", gdb.interrupt)
	gdb.value.attrs["wait"] = workflowBuiltin("wait", gdb.wait)
	gdb.value.attrs["with_register"] = workflowBuiltin("with_register", gdb.withRegister)
	gdb.value.attrs["with_state"] = workflowBuiltin("with_state", gdb.withState)
	return gdb
}

func (g *workflowGDB) writeMemory(_ *starlark.Thread, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	address, err := workflowUint(args, 0)
	if err != nil {
		return nil, err
	}
	data, ok := args[1].(starlark.Bytes)
	if !ok || address > uint64(len(g.memory)) || uint64(len(data)) > uint64(len(g.memory))-address {
		return nil, fmt.Errorf("fake GDB memory write is out of bounds")
	}
	copy(g.memory[address:], string(data))
	return starlark.None, nil
}

func (g *workflowGDB) readMemory(_ *starlark.Thread, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	address, err := workflowUint(args, 0)
	if err != nil {
		return nil, err
	}
	size, err := workflowUint(args, 1)
	if err != nil || address > uint64(len(g.memory)) || size > uint64(len(g.memory))-address {
		return nil, fmt.Errorf("fake GDB memory range is out of bounds")
	}
	return starlark.Bytes(string(g.memory[address : address+size])), nil
}

func (g *workflowGDB) searchMemory(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	address, err := workflowUint(args, 0)
	if err != nil {
		return nil, err
	}
	length, err := workflowUint(args, 1)
	if err != nil || address > uint64(len(g.memory)) || length > uint64(len(g.memory))-address {
		return nil, fmt.Errorf("fake GDB search range is out of bounds")
	}
	pattern, ok := args[2].(starlark.Bytes)
	if !ok || len(pattern) == 0 {
		return nil, fmt.Errorf("fake GDB pattern must be non-empty bytes")
	}
	limit := uint64(1024)
	for _, item := range kwargs {
		if string(item[0].(starlark.String)) == "limit" {
			limit, err = workflowValueUint(item[1])
			if err != nil {
				return nil, err
			}
		}
	}
	var hits []starlark.Value
	data := g.memory[address : address+length]
	for index := 0; index+len(pattern) <= len(data) && uint64(len(hits)) < limit; index++ {
		if string(data[index:index+len(pattern)]) == string(pattern) {
			hits = append(hits, starlark.MakeUint64(address+uint64(index)))
		}
	}
	return starlark.NewList(hits), nil
}

func (g *workflowGDB) readRegisters(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	return workflowRegisterDict(g.registers), nil
}

func (g *workflowGDB) writeRegister(_ *starlark.Thread, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	name, ok := starlark.AsString(args[0])
	if !ok {
		return nil, fmt.Errorf("fake register name must be a string")
	}
	value, err := workflowValueUint(args[1])
	if err != nil {
		return nil, err
	}
	g.registers[name] = value
	return starlark.None, nil
}

func (g *workflowGDB) breakpoint(_ *starlark.Thread, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	address, err := workflowUint(args, 0)
	if err != nil {
		return nil, err
	}
	point := newWorkflowPoint(address, 1, "breakpoint")
	g.points = append(g.points, point)
	return point, nil
}

func (g *workflowGDB) watchpoint(_ *starlark.Thread, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	address, err := workflowUint(args, 0)
	if err != nil {
		return nil, err
	}
	size, err := workflowUint(args, 1)
	if err != nil {
		return nil, err
	}
	point := newWorkflowPoint(address, size, "watchpoint")
	g.points = append(g.points, point)
	return point, nil
}

func (g *workflowGDB) resume(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	g.continues++
	return starlark.None, nil
}

func (g *workflowGDB) step(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	g.steps++
	return starlark.None, nil
}

func (g *workflowGDB) interrupt(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	g.interrupts++
	return starlark.None, nil
}

func (g *workflowGDB) wait(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	if len(g.stops) == 0 {
		return nil, fmt.Errorf("fake GDB has no queued stop")
	}
	stop := g.stops[0]
	g.stops = g.stops[1:]
	return stop, nil
}

func (g *workflowGDB) withRegister(thread *starlark.Thread, args starlark.Tuple, _ []starlark.Tuple) (result starlark.Value, err error) {
	if len(args) != 3 {
		return nil, fmt.Errorf("fake with_register expects name, value, callback")
	}
	name, ok := starlark.AsString(args[0])
	if !ok {
		return nil, fmt.Errorf("fake register name must be a string")
	}
	value, err := workflowValueUint(args[1])
	if err != nil {
		return nil, err
	}
	callback, ok := args[2].(starlark.Callable)
	if !ok {
		return nil, fmt.Errorf("fake callback is not callable")
	}
	old := g.registers[name]
	g.registers[name] = value
	defer func() {
		g.registers[name] = old
		g.restoreSeen = true
	}()
	return starlark.Call(thread, callback, nil, nil)
}

func (g *workflowGDB) withState(thread *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (result starlark.Value, err error) {
	var registers, memory *starlark.List
	var callback starlark.Callable
	timeout := starlarkNumber(30)
	if err := starlark.UnpackArgs("with_state", args, kwargs, "registers", &registers, "memory", &memory, "callback", &callback, "timeout?", &timeout); err != nil {
		return nil, err
	}
	savedRegisters := map[string]uint64{}
	for index := 0; index < registers.Len(); index++ {
		name, ok := starlark.AsString(registers.Index(index))
		if !ok {
			return nil, fmt.Errorf("fake state register must be a string")
		}
		savedRegisters[name] = g.registers[name]
	}
	type snapshot struct {
		address uint64
		data    []byte
	}
	snapshots := make([]snapshot, 0, memory.Len())
	for index := 0; index < memory.Len(); index++ {
		item := memory.Index(index).(starlark.Tuple)
		address, err := workflowValueUint(item[0])
		if err != nil {
			return nil, err
		}
		size, err := workflowValueUint(item[1])
		if err != nil || address > uint64(len(g.memory)) || size > uint64(len(g.memory))-address {
			return nil, fmt.Errorf("fake state memory range is out of bounds")
		}
		snapshots = append(snapshots, snapshot{address: address, data: append([]byte(nil), g.memory[address:address+size]...)})
	}
	defer func() {
		for name, value := range savedRegisters {
			g.registers[name] = value
		}
		for _, snapshot := range snapshots {
			copy(g.memory[snapshot.address:], snapshot.data)
		}
		g.restoreSeen = true
	}()
	return starlark.Call(thread, callback, nil, nil)
}

func (g *workflowGDB) String() string        { return g.value.String() }
func (g *workflowGDB) Type() string          { return g.value.Type() }
func (g *workflowGDB) Freeze()               {}
func (g *workflowGDB) Truth() starlark.Bool  { return starlark.True }
func (g *workflowGDB) Hash() (uint32, error) { return g.value.Hash() }
func (g *workflowGDB) Attr(name string) (starlark.Value, error) {
	return g.value.Attr(name)
}
func (g *workflowGDB) AttrNames() []string         { return g.value.AttrNames() }
func (g *workflowGDB) DebugReady() <-chan struct{} { return g.value.DebugReady() }
func (g *workflowGDB) put32(address int, value uint32) {
	binary.LittleEndian.PutUint32(g.memory[address:], value)
}
func (g *workflowGDB) put16(address int, value uint16) {
	binary.LittleEndian.PutUint16(g.memory[address:], value)
}
func (g *workflowGDB) putBytes(address int, value []byte) { copy(g.memory[address:], value) }

type workflowKD struct {
	value    *workflowObject
	memory   []byte
	events   []starlark.Value
	breakins int
	points   []*workflowPoint
}

func newWorkflowKD(memory []byte, events ...starlark.Value) *workflowKD {
	kd := &workflowKD{memory: memory, events: events}
	ready := make(chan struct{})
	kd.value = &workflowObject{typeName: "fake_kd", ready: ready, attrs: starlark.StringDict{}}
	readMemory := func(_ *starlark.Thread, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		address, err := workflowUint(args, 0)
		if err != nil {
			return nil, err
		}
		size, err := workflowUint(args, 1)
		if err != nil || address > uint64(len(kd.memory)) || size > uint64(len(kd.memory))-address {
			return nil, fmt.Errorf("fake KD memory range is out of bounds")
		}
		return starlark.Bytes(string(kd.memory[address : address+size])), nil
	}
	kd.value.attrs["read_physical"] = workflowBuiltin("read_physical", readMemory)
	kd.value.attrs["read_virtual"] = workflowBuiltin("read_virtual", readMemory)
	kd.value.attrs["write_physical"] = workflowBuiltin("write_physical", func(_ *starlark.Thread, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		address, err := workflowUint(args, 0)
		if err != nil {
			return nil, err
		}
		data, ok := args[1].(starlark.Bytes)
		if !ok || address > uint64(len(kd.memory)) || uint64(len(data)) > uint64(len(kd.memory))-address {
			return nil, fmt.Errorf("fake KD physical write is out of bounds")
		}
		copy(kd.memory[address:], []byte(data))
		return starlark.None, nil
	})
	kd.value.attrs["next_event"] = workflowBuiltin("next_event", func(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if len(kd.events) == 0 {
			return nil, fmt.Errorf("fake KD has no queued event")
		}
		event := kd.events[0]
		kd.events = kd.events[1:]
		return event, nil
	})
	kd.value.attrs["breakin"] = workflowBuiltin("breakin", func(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		kd.breakins++
		return starlark.None, nil
	})
	kd.value.attrs["breakpoint"] = workflowBuiltin("breakpoint", func(_ *starlark.Thread, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		address, err := workflowUint(args, 0)
		if err != nil {
			return nil, err
		}
		point := newWorkflowPoint(address, 1, "kd_breakpoint")
		kd.points = append(kd.points, point)
		return point, nil
	})
	return kd
}

func (k *workflowKD) String() string        { return k.value.String() }
func (k *workflowKD) Type() string          { return k.value.Type() }
func (k *workflowKD) Freeze()               {}
func (k *workflowKD) Truth() starlark.Bool  { return starlark.True }
func (k *workflowKD) Hash() (uint32, error) { return k.value.Hash() }
func (k *workflowKD) Attr(name string) (starlark.Value, error) {
	return k.value.Attr(name)
}
func (k *workflowKD) AttrNames() []string         { return k.value.AttrNames() }
func (k *workflowKD) DebugReady() <-chan struct{} { return k.value.DebugReady() }

type workflowVM struct {
	value       *workflowObject
	pointerOps  int
	screenshots int
}

func newWorkflowVM() *workflowVM {
	vm := &workflowVM{}
	ready := make(chan struct{})
	vm.value = &workflowObject{typeName: "fake_vm", ready: ready, attrs: starlark.StringDict{}}
	vm.value.attrs["pointer"] = workflowBuiltin("pointer", func(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		vm.pointerOps++
		return starlark.None, nil
	})
	vm.value.attrs["screenshot"] = workflowBuiltin("screenshot", func(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		vm.screenshots++
		return &starfile.Bytes{Name: "checkpoint.png", Data: []byte("png")}, nil
	})
	return vm
}

func (v *workflowVM) String() string        { return v.value.String() }
func (v *workflowVM) Type() string          { return v.value.Type() }
func (v *workflowVM) Freeze()               {}
func (v *workflowVM) Truth() starlark.Bool  { return starlark.True }
func (v *workflowVM) Hash() (uint32, error) { return v.value.Hash() }
func (v *workflowVM) Attr(name string) (starlark.Value, error) {
	return v.value.Attr(name)
}
func (v *workflowVM) AttrNames() []string         { return v.value.AttrNames() }
func (v *workflowVM) DebugReady() <-chan struct{} { return v.value.DebugReady() }

func TestHistoricalDebuggerWorkflowsComposeInStarlark(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	gdbModule := workflowModule(t, thread, "@stdlib//debug:gdb.star")
	traceModule := workflowModule(t, thread, "@stdlib//debug:trace.star")
	processModule := workflowModule(t, thread, "@stdlib//windows:process.star")
	kdModule := workflowModule(t, thread, "@stdlib//windows:kd.star")
	symbolModule := workflowModule(t, thread, "@stdlib//windows:symbols.star")
	automationModule := workflowModule(t, thread, "@stdlib//vmm:automation.star")

	gdb := newWorkflowGDB(0x10000)
	gdb.put16(0x7c00, 0xaa55)
	if got := workflowCall(t, thread, gdbModule, "read_u16", gdb, starlark.MakeInt(0x7c00)); got.String() != "43605" {
		t.Fatalf("real-mode boot word = %s", got)
	}
	gdb.putBytes(0x7d00, []byte{'W', 0, 'i', 0, 'n', 0, '2', 0, 'K', 0, 0, 0})
	if got := workflowCall(t, thread, gdbModule, "read_utf16_c_string", gdb, starlark.MakeInt(0x7d00), starlark.MakeInt(12)); got != starlark.String("Win2K") {
		t.Fatalf("UTF-16 target string = %s", got)
	}

	gdb.registers["eax"] = 0x11
	gdb.registers["ebx"] = 0x22
	gdb.registers["ecx"] = 0x33
	gdb.registers["edx"] = 0x44
	gdb.registers["esi"] = 0x55
	gdb.registers["edi"] = 0x66
	gdb.registers["ebp"] = 0xe000
	gdb.registers["esp"] = 0xf000
	gdb.registers["eip"] = 0x7000
	gdb.registers["eflags"] = 0x202
	for index := 0xb000; index < 0xf000; index++ {
		gdb.memory[index] = byte(index)
	}
	stackBefore := append([]byte(nil), gdb.memory[0xb000:0xf000]...)
	gdb.stops = append(gdb.stops, workflowStop(0xeff9, map[string]uint64{
		"eax": 0xbeef, "ebx": 0, "ecx": 0, "edx": 0, "esi": 0, "edi": 0,
		"ebp": 0, "esp": 0xefec, "eip": 0xeff9, "eflags": 0x202,
	}))
	call := workflowCallKw(t, thread, gdbModule, "inferior_call", starlark.Tuple{
		gdb, starlark.MakeInt(0x123456), starlark.NewList([]starlark.Value{starlark.MakeInt(7), starlark.Bytes("data")}),
	}, []starlark.Tuple{{starlark.String("stack_size"), starlark.MakeInt(0x4000)}}).(*starlark.Dict)
	callValue, found, err := call.Get(starlark.String("value"))
	if err != nil || !found || callValue.String() != "48879" {
		t.Fatalf("inferior call result = %s, found=%t, err=%v", callValue, found, err)
	}
	if gdb.registers["eax"] != 0x11 || gdb.registers["esp"] != 0xf000 || gdb.registers["eip"] != 0x7000 || string(gdb.memory[0xb000:0xf000]) != string(stackBefore) {
		t.Fatal("inferior call did not restore target registers and stack memory")
	}

	for _, pc := range []uint64{0x100, 0x101, 0x100, 0x200, 0x201, 0x200} {
		gdb.stops = append(gdb.stops, workflowStop(pc, map[string]uint64{"eip": pc, "esp": 0x8000, "ebp": 0x8100}))
	}
	addresses := starlark.NewList([]starlark.Value{starlark.MakeInt(0x100), starlark.MakeInt(0x200)})
	ordered := workflowCall(t, thread, traceModule, "ordered_breakpoints", gdb, addresses, starlark.MakeInt(2))
	if ordered.(*starlark.List).Len() != 4 || len(gdb.points) != 4 {
		t.Fatalf("ordered breakpoint workflow did not clean up: stops=%s points=%#v", ordered, gdb.points)
	}
	for _, point := range gdb.points {
		if !point.removed {
			t.Fatalf("ordered breakpoint workflow left a point installed: %#v", point)
		}
	}
	if gdb.steps != 2 {
		t.Fatalf("ordered breakpoint workflow stepped %d times, want 2", gdb.steps)
	}
	gdb.stops = append(gdb.stops,
		workflowStop(0x333, map[string]uint64{"eip": 0x333, "esp": 0x8000}),
		workflowStop(0x444, map[string]uint64{"eip": 0x444, "esp": 0x8000}),
	)
	filtered := workflowCall(t, thread, gdbModule, "run_to", gdb, starlark.MakeInt(0x444))
	filteredPC, _ := filtered.(*starlarkRecord).Attr("pc")
	if filteredPC.String() != "1092" {
		t.Fatalf("run_to accepted an unrelated stop: %s", filtered)
	}
	gdb.stops = append(gdb.stops,
		workflowStop(0x555, map[string]uint64{"eip": 0x555, "esp": 0x8000}),
		workflowStop(0x666, map[string]uint64{"eip": 0x666, "esp": 0x8000}),
	)
	matched := workflowCall(t, thread, gdbModule, "wait_for_pcs", gdb,
		starlark.NewList([]starlark.Value{starlark.MakeInt(0x444), starlark.MakeInt(0x666)}),
	).(*starlark.Dict)
	matchedAddress, _, err := matched.Get(starlark.String("address"))
	if err != nil || matchedAddress.String() != "1638" {
		t.Fatalf("wait_for_pcs match = %s, err=%v", matched, err)
	}
	stopCount, _, err := matched.Get(starlark.String("stop_count"))
	if err != nil || stopCount.String() != "2" {
		t.Fatalf("wait_for_pcs stop count = %s, err=%v", matched, err)
	}

	gdb.put32(0x8000, 0x9000)
	gdb.putBytes(0x9020, []byte{0xde, 0xad, 0xbe, 0xef})
	entry := workflowStop(0x7000, map[string]uint64{"eip": 0x7000, "esp": 0x8000, "ebp": 0x8100})
	gdb.stops = append(gdb.stops,
		workflowStop(0x9022, map[string]uint64{"eip": 0x9022, "esp": 0x8000, "ebp": 0x8100}),
		workflowStop(0xa000, map[string]uint64{"eip": 0xa000, "esp": 0x8000, "ebp": 0x8100}),
	)
	watchAddress := workflowBuiltin("watch_address", func(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return starlark.MakeInt(0xa000), nil
	})
	workflowCall(t, thread, traceModule, "chained_return_search_watch",
		gdb, entry, starlark.Bytes("\xde\xad\xbe\xef"), starlark.MakeInt(0), starlark.MakeInt(2), watchAddress, starlark.MakeInt(4), starlark.MakeInt(1))
	last := gdb.points[len(gdb.points)-1]
	if last.kind != "watchpoint" || last.size != 4 || !last.removed {
		t.Fatalf("return/search/watch workflow = %#v", last)
	}

	gdb.stops = append(gdb.stops, workflowStop(0x7100, map[string]uint64{"eip": 0x7100, "esp": 0x8000, "ebp": 0x8100}))
	workflowCall(t, thread, traceModule, "delayed_snapshot", gdb, starlark.MakeInt(0))
	if gdb.interrupts != 1 {
		t.Fatalf("delayed snapshot interrupts = %d", gdb.interrupts)
	}
	gdb.putBytes(0x7200, []byte{0x90, 0x90})
	gdb.stops = append(gdb.stops,
		workflowStop(0x7201, map[string]uint64{"eip": 0x7201, "esp": 0x8000, "ebp": 0x8100}),
		workflowStop(0x7202, map[string]uint64{"eip": 0x7202, "esp": 0x8000, "ebp": 0x8100}),
	)
	stepped := workflowCall(t, thread, traceModule, "selective_step_trace",
		gdb, workflowStop(0x7200, map[string]uint64{"eip": 0x7200, "esp": 0x8000, "ebp": 0x8100}), starlark.MakeInt(2))
	if stepped.(*starlark.List).Len() != 2 || gdb.steps != 4 {
		t.Fatalf("selective step workflow = %s, steps=%d", stepped, gdb.steps)
	}

	configureProcessMemory(gdb)
	offsets := workflowDict(map[string]starlark.Value{
		"peb_ldr": starlark.MakeInt(0), "ldr_list": starlark.MakeInt(0x10),
		"entry_links": starlark.MakeInt(8), "entry_base": starlark.MakeInt(0x18),
		"entry_size": starlark.MakeInt(0x20), "entry_name": starlark.MakeInt(0x24),
	})
	modules := workflowCall(t, thread, processModule, "peb_modules", gdb, starlark.MakeInt(0x222000), starlark.MakeInt(0x1000), offsets)
	if modules.(*starlark.List).Len() != 1 || gdb.registers["cr3"] != 0x111000 || !gdb.restoreSeen {
		t.Fatalf("PEB traversal did not restore CR3: modules=%s cr3=%#x", modules, gdb.registers["cr3"])
	}

	kdMemory := make([]byte, 0x10000)
	putWorkflow32(kdMemory, 0x6000, 0x7008)
	putWorkflow32(kdMemory, 0x6004, 0x7008)
	putWorkflow32(kdMemory, 0x7008, 0x6000)
	putWorkflow32(kdMemory, 0x700c, 0x6000)
	putWorkflow32(kdMemory, 0x7010, 4)
	putWorkflow32(kdMemory, 0x7014, 0x222000)
	putWorkflow32(kdMemory, 0x7018, 0x1000)
	copy(kdMemory[0x7020:], "test.exe\x00")
	loadEvent := newStarlarkRecord(starlark.StringDict{
		"kind": starlark.String("load_symbols"), "path": starlark.String("\\SystemRoot\\ntoskrnl.exe"),
		"base": starlark.MakeInt(0x80400000), "size": starlark.MakeInt(0x200000), "unload": starlark.False,
	})
	kd := newWorkflowKD(kdMemory, loadEvent)
	processOffsets := workflowDict(map[string]starlark.Value{
		"links": starlark.MakeInt(8), "pid": starlark.MakeInt(0x10), "directory_table_base": starlark.MakeInt(0x14),
		"peb": starlark.MakeInt(0x18), "image_name": starlark.MakeInt(0x20), "image_name_size": starlark.MakeInt(16),
	})
	processes := workflowCall(t, thread, processModule, "eprocesses", kd, starlark.MakeInt(0x6000), processOffsets)
	if processes.(*starlark.List).Len() != 1 {
		t.Fatalf("EPROCESS traversal = %s", processes)
	}
	process := processes.(*starlark.List).Index(0).(*starlark.Dict)
	imageName, found, err := process.Get(starlark.String("image_name"))
	if err != nil || !found || imageName != starlark.String("test.exe") {
		t.Fatalf("EPROCESS image name = %v, found=%t, err=%v", imageName, found, err)
	}
	foundProcess := workflowCallKw(t, thread, processModule, "find_eprocess", starlark.Tuple{kd, starlark.MakeInt(0x6000), processOffsets}, []starlark.Tuple{{starlark.String("image_name"), starlark.String("TEST.EXE")}})
	if foundProcess == starlark.None {
		t.Fatal("case-insensitive EPROCESS lookup failed")
	}
	putWorkflow32(kdMemory, 0x500, 0x7000)
	if head := workflowCall(t, thread, processModule, "process_list_head", kd, starlark.MakeInt(0), starlark.MakeInt(0x500), processOffsets); head.String() != "24576" {
		t.Fatalf("active process list head = %s, want 24576", head)
	}
	insertion := workflowCallKw(t, thread, processModule, "wait_for_eprocess_insertion", starlark.Tuple{kd, starlark.MakeInt(0x6000), processOffsets}, []starlark.Tuple{{starlark.String("image_name"), starlark.String("test.exe")}}).(*starlark.Dict)
	if selected, _, _ := insertion.Get(starlark.String("process")); selected == starlark.None {
		t.Fatal("existing EPROCESS was not selected before installing a watchpoint")
	}
	processForImage := workflowDict(map[string]starlark.Value{
		"address": starlark.MakeInt(0x7000), "directory_table_base": starlark.MakeInt(0x222000), "peb": starlark.MakeInt(0x2000),
	})
	gdb.put32(0x2008, 0x400000)
	gdb.put32(0x7018, 0x2000)
	if base := workflowCall(t, thread, processModule, "process_image_base", gdb, processForImage); base.String() != "4194304" || gdb.registers["cr3"] != 0x111000 {
		t.Fatalf("process image base = %s, restored cr3=%#x", base, gdb.registers["cr3"])
	}
	readyProcess := workflowCall(t, thread, processModule, "wait_for_process_peb", gdb, processForImage, processOffsets).(*starlark.Dict)
	if selected, _, _ := readyProcess.Get(starlark.String("process")); selected == starlark.None {
		t.Fatal("existing process PEB was not returned immediately")
	}
	nt61Offsets := workflowCall(t, thread, processModule, "nt61_x86_eprocess_offsets").(*starlark.Dict)
	links, _, _ := nt61Offsets.Get(starlark.String("links"))
	if links.String() != "184" {
		t.Fatalf("NT 6.1 EPROCESS links offset = %s", links)
	}
	putWorkflow32(kdMemory, 0x1000, 0x2001)
	putWorkflow32(kdMemory, 0x2004, 0x3001)
	putWorkflow32(kdMemory, 0x310c, 0x1200)
	putWorkflow32(kdMemory, 0x320c, 0x1300)
	putWorkflow32(kdMemory, 0x3210, 0x1300)
	putWorkflow32(kdMemory, 0x3300, 0x120c)
	putWorkflow32(kdMemory, 0x3304, 0x120c)
	putWorkflow32(kdMemory, 0x3318, 0x400000)
	putWorkflow32(kdMemory, 0x3320, 0x22000)
	putWorkflow16(kdMemory, 0x3324, 30)
	putWorkflow16(kdMemory, 0x3326, 32)
	putWorkflow32(kdMemory, 0x3328, 0x1400)
	putWorkflow16(kdMemory, 0x332c, 16)
	putWorkflow16(kdMemory, 0x332e, 18)
	putWorkflow32(kdMemory, 0x3330, 0x1500)
	copy(kdMemory[0x3400:], []byte("C\x00:\x00\\\x00W\x00i\x00n\x00\\\x00t\x00e\x00s\x00t\x00.\x00e\x00x\x00e\x00"))
	copy(kdMemory[0x3500:], []byte("t\x00e\x00s\x00t\x00.\x00e\x00x\x00e\x00"))
	processForKDModules := workflowDict(map[string]starlark.Value{
		"directory_table_base": starlark.MakeInt(0x1000), "peb": starlark.MakeInt(0x1100),
	})
	pebOffsets := workflowDict(map[string]starlark.Value{
		"entry_base":      starlark.MakeInt(0x18),
		"entry_full_name": starlark.MakeInt(0x24),
		"entry_links":     starlark.MakeInt(0x00),
		"entry_name":      starlark.MakeInt(0x2c),
		"entry_size":      starlark.MakeInt(0x20),
		"ldr_list":        starlark.MakeInt(0x0c),
		"peb_image_base":  starlark.MakeInt(0x08),
		"peb_ldr":         starlark.MakeInt(0x0c),
	})
	kdModules := workflowCallKw(t, thread, processModule, "process_modules", starlark.Tuple{kd, processForKDModules, pebOffsets}, []starlark.Tuple{{starlark.String("pae"), starlark.False}}).(*starlark.List)
	if kdModules.Len() != 1 {
		t.Fatalf("KD PEB traversal = %s", kdModules)
	}
	kdModuleRecord := kdModules.Index(0).(*starlark.Dict)
	kdModuleName, _, _ := kdModuleRecord.Get(starlark.String("name"))
	if kdModuleName != starlark.String("test.exe") {
		t.Fatalf("KD PEB module name = %s", kdModuleName)
	}
	workflowCallKw(t, thread, processModule, "write_process_virtual", starlark.Tuple{kd, processForKDModules, starlark.MakeInt(0x1600), starlark.Bytes("patched")}, []starlark.Tuple{{starlark.String("pae"), starlark.False}})
	if got := string(kdMemory[0x3600 : 0x3600+7]); got != "patched" {
		t.Fatalf("KD process physical write = %q", got)
	}
	breakpoint := workflowCallKw(t, thread, processModule, "install_process_breakpoint", starlark.Tuple{kd, processForKDModules, starlark.MakeInt(0x1600)}, []starlark.Tuple{{starlark.String("pae"), starlark.False}}).(*starlark.Dict)
	if kdMemory[0x3600] != 0xcc {
		t.Fatalf("KD process breakpoint byte = %#x", kdMemory[0x3600])
	}
	workflowCall(t, thread, processModule, "restore_process_breakpoint", kd, breakpoint)
	if got := string(kdMemory[0x3600 : 0x3600+7]); got != "patched" {
		t.Fatalf("KD restored process breakpoint = %q", got)
	}
	workflowCall(t, thread, processModule, "rearm_process_breakpoint", kd, breakpoint)
	workflowCall(t, thread, processModule, "restore_process_breakpoint", kd, breakpoint)
	gdb.put32(0x3034, 0x3100)
	gdb.put16(0x3100, 15)
	gdb.put16(0x3102, 7601)
	gdb.putBytes(0x3104, []byte{6, 0})
	gdb.put16(0x3106, 3)
	gdb.put16(0x3108, 0x14c)
	gdb.put32(0x3110, 0x82852000)
	gdb.put32(0x3114, 0xffffffff)
	gdb.put32(0x3118, 0x82996c10)
	gdb.put32(0x311c, 0xffffffff)
	gdb.put32(0x3120, 0x82bc2fec)
	gdb.put32(0x3124, 0xffffffff)
	debuggerState := workflowCall(t, thread, processModule, "nt_x86_debugger_state", gdb, starlark.MakeInt(0x3000)).(*starlark.Dict)
	kernelBase, _, _ := debuggerState.Get(starlark.String("kernel_base"))
	loadedModules, _, _ := debuggerState.Get(starlark.String("loaded_module_list"))
	if kernelBase.String() != "2189762560" || loadedModules.String() != "2191092752" {
		t.Fatalf("x86 debugger state = %s", debuggerState)
	}
	event := workflowCall(t, thread, kdModule, "delayed_breakin", kd, starlark.MakeInt(0))
	if kd.breakins != 1 {
		t.Fatalf("delayed KD break-ins = %d", kd.breakins)
	}
	resolver := workflowCall(t, thread, symbolModule, "state")
	if workflowCall(t, thread, symbolModule, "update", resolver, event) != starlark.True {
		t.Fatal("KD module event was not tracked")
	}
	location := workflowCall(t, thread, symbolModule, "locate", resolver, starlark.MakeInt(0x80400120))
	if location == starlark.None {
		t.Fatal("KD module address was not symbolized")
	}
	signExtendedEvent := newStarlarkRecord(starlark.StringDict{
		"kind": starlark.String("load_symbols"), "path": starlark.String("\\SystemRoot\\ntkrnlpa.exe"),
		"base": starlark.MakeUint64(0xffffffff81800000), "size": starlark.MakeInt(0x200000), "unload": starlark.False,
	})
	if workflowCall(t, thread, symbolModule, "update", resolver, signExtendedEvent) != starlark.True {
		t.Fatal("sign-extended KD module event was not tracked")
	}
	if location := workflowCall(t, thread, symbolModule, "locate", resolver, starlark.MakeUint64(0x81800120)); location == starlark.None {
		t.Fatal("sign-extended x86 KD module base was not canonicalized")
	}
	workflowCallKw(t, thread, kdModule, "break_on_module", starlark.Tuple{kd, event}, []starlark.Tuple{{starlark.String("rva"), starlark.MakeInt(0x120)}})
	if len(kd.points) != 1 || kd.points[0].address != 0x80400120 {
		t.Fatalf("KD module breakpoint = %#v", kd.points)
	}

	vm := newWorkflowVM()
	procedure := workflowBuiltin("ui_procedure", func(thread *starlark.Thread, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return starlark.Call(thread, automationModule["click"].(starlark.Callable), starlark.Tuple{args[0], starlark.MakeInt(10), starlark.MakeInt(20)}, nil)
	})
	captures := workflowCall(t, thread, automationModule, "repeat_ui", vm, procedure, starlark.MakeInt(3))
	// Each complete click moves to the target, presses, and releases. Keeping
	// those transitions distinct prevents a held button from leaking into the
	// next portable automation operation.
	if captures.(*starlark.List).Len() != 3 || vm.pointerOps != 9 || vm.screenshots != 3 {
		t.Fatalf("UI automation captures=%s pointer=%d screenshots=%d", captures, vm.pointerOps, vm.screenshots)
	}
}

func TestPortableEventPumpDispatchesUntilPredicate(t *testing.T) {
	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	module := workflowModule(t, thread, "@stdlib//vmm:automation.star")
	ready := make(chan struct{}, 2)
	ready <- struct{}{}
	ready <- struct{}{}
	events := []starlark.Value{
		newStarlarkRecord(starlark.StringDict{"kind": starlark.String("started")}),
		newStarlarkRecord(starlark.StringDict{"kind": starlark.String("desktop")}),
	}
	index := 0
	source := &workflowObject{typeName: "fake_event_source", ready: ready, attrs: starlark.StringDict{}}
	source.attrs["next_event"] = workflowBuiltin("next_event", func(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if index >= len(events) {
			return nil, fmt.Errorf("event queue exhausted")
		}
		value := events[index]
		index++
		return value, nil
	})
	handled := 0
	handler := workflowBuiltin("handle_started", func(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		handled++
		return starlark.None, nil
	})
	until := workflowBuiltin("until_desktop", func(_ *starlark.Thread, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		kind, _ := args[1].(starlark.HasAttrs).Attr("kind")
		return starlark.Bool(kind == starlark.String("desktop")), nil
	})
	handlers := starlark.NewDict(1)
	_ = handlers.SetKey(starlark.String("started"), handler)
	result := workflowCallKw(t, thread, module, "pump_events", starlark.Tuple{
		starlark.NewList([]starlark.Value{source}),
	}, []starlark.Tuple{
		{starlark.String("handlers"), handlers},
		{starlark.String("until"), until},
		{starlark.String("timeout"), starlark.MakeInt(1)},
	}).(*starlark.Dict)
	count, _, _ := result.Get(starlark.String("count"))
	if count.String() != "2" || handled != 1 {
		t.Fatalf("event pump result=%s handled=%d", result, handled)
	}
}

func workflowBuiltin(name string, function func(*starlark.Thread, starlark.Tuple, []starlark.Tuple) (starlark.Value, error)) *starlark.Builtin {
	return starlark.NewBuiltin(name, func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return function(thread, args, kwargs)
	})
}

func workflowModule(t *testing.T, thread *starlark.Thread, name string) starlark.StringDict {
	t.Helper()
	module, err := thread.Load(thread, name)
	if err != nil {
		t.Fatal(err)
	}
	return module
}

func workflowCall(t *testing.T, thread *starlark.Thread, module starlark.StringDict, name string, args ...starlark.Value) starlark.Value {
	t.Helper()
	return workflowCallKw(t, thread, module, name, starlark.Tuple(args), nil)
}

func workflowCallKw(t *testing.T, thread *starlark.Thread, module starlark.StringDict, name string, args starlark.Tuple, kwargs []starlark.Tuple) starlark.Value {
	t.Helper()
	callable, ok := module[name].(starlark.Callable)
	if !ok {
		t.Fatalf("%s is not callable", name)
	}
	value, err := starlark.Call(thread, callable, args, kwargs)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return value
}

func workflowUint(args starlark.Tuple, index int) (uint64, error) {
	if index >= len(args) {
		return 0, fmt.Errorf("missing fake argument %d", index)
	}
	return workflowValueUint(args[index])
}

func workflowValueUint(value starlark.Value) (uint64, error) {
	integer, ok := value.(starlark.Int)
	if !ok {
		return 0, fmt.Errorf("got %s, want int", value.Type())
	}
	number, ok := integer.Uint64()
	if !ok {
		return 0, fmt.Errorf("integer is negative or too large")
	}
	return number, nil
}

func workflowRegisterDict(registers map[string]uint64) *starlark.Dict {
	dict := starlark.NewDict(len(registers))
	for name, value := range registers {
		_ = dict.SetKey(starlark.String(name), starlark.MakeUint64(value))
	}
	return dict
}

func workflowStop(pc uint64, registers map[string]uint64) *starlarkRecord {
	return newStarlarkRecord(starlark.StringDict{
		"pc": starlark.MakeUint64(pc), "reason": starlark.String("breakpoint"), "registers": workflowRegisterDict(registers),
	})
}

func workflowDict(values map[string]starlark.Value) *starlark.Dict {
	dict := starlark.NewDict(len(values))
	for name, value := range values {
		_ = dict.SetKey(starlark.String(name), value)
	}
	return dict
}

func configureProcessMemory(gdb *workflowGDB) {
	gdb.put32(0x1000, 0x2000)
	gdb.put32(0x2010, 0x3008)
	gdb.put32(0x3008, 0x2010)
	gdb.put32(0x3018, 0x400000)
	gdb.put32(0x3020, 0x1000)
	gdb.put16(0x3024, 8)
	gdb.put16(0x3026, 10)
	gdb.put32(0x3028, 0x5000)
	gdb.putBytes(0x5000, []byte{'t', 0, 'e', 0, 's', 0, 't', 0, 0, 0})
}

func putWorkflow32(data []byte, address int, value uint32) {
	binary.LittleEndian.PutUint32(data[address:], value)
}

func putWorkflow16(data []byte, address int, value uint16) {
	binary.LittleEndian.PutUint16(data[address:], value)
}
