package uefi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/emulator/arm64"
	"github.com/tinyrange/trex/emulator/cpu"
	"hash/crc32"
	"j5.nz/cc/devices/ramfb"
	"j5.nz/cc/hypervisor"
	"maps"
	"slices"
	"strconv"
)

// NativeExecution is independent of the emulator checkpoint. It owns a copy of
// RAM and resumes the architectural state after validated ExitBootServices.
type NativeExecution struct {
	pci                                                         hypervisor.MMIODevice
	Keyboard, Pointer                                           hypervisor.InputDevice
	cpu                                                         hypervisor.ARM64
	ram                                                         []byte
	base                                                        uint64
	firmware                                                    *Machine
	gates                                                       map[uint16]string
	virtualMap                                                  []runtimeRange
	WindowsDebug                                                bool
	Modules                                                     map[uint64]NativeModule
	devices                                                     []hypervisor.MMIODevice
	Counts                                                      map[string]uint64
	MMIOLimit                                                   int
	MMIO                                                        []MMIOAccess
	Console                                                     []string
	consoleBytes                                                uint64
	Display                                                     *ramfb.Device
	Disk                                                        *blockstar.OverlayDevice
	clockBase, clockFrequency, firmwareTicks, firmwareFrequency uint64
}

type nativePhysical struct{ n *NativeExecution }

func (m nativePhysical) ReadPhysical(a uint64, b []byte) error  { return m.n.ReadMemory(a, b, cpu.Read) }
func (m nativePhysical) WritePhysical(a uint64, b []byte) error { return m.n.WriteMemory(a, b) }

func (n *NativeExecution) AttachRAMFB(base uint64) error {
	if n.Display != nil {
		return fmt.Errorf("native RAMFB already attached")
	}
	d, err := ramfb.New(base, nativePhysical{n})
	if err != nil {
		return err
	}
	n.Display = d
	n.devices = append(n.devices, observedMMIO{d, n})
	return nil
}

// MMIOAccess is a bounded observation of an actual device transaction.
type MMIOAccess struct {
	Address, Value uint64
	Size           int
	Write          bool
}
type observedMMIO struct {
	hypervisor.MMIODevice
	owner *NativeExecution
}

func (d observedMMIO) observe(a MMIOAccess) {
	n := d.owner
	if n.MMIOLimit == 0 {
		return
	}
	if len(n.MMIO) >= n.MMIOLimit {
		copy(n.MMIO, n.MMIO[len(n.MMIO)-n.MMIOLimit+1:])
		n.MMIO = n.MMIO[:n.MMIOLimit-1]
	}
	n.MMIO = append(n.MMIO, a)
}
func (d observedMMIO) Read(a uint64, s int) (uint64, error) {
	v, e := d.MMIODevice.Read(a, s)
	if e == nil {
		d.observe(MMIOAccess{a, v, s, false})
	}
	return v, e
}
func (d observedMMIO) Write(a uint64, s int, v uint64) error {
	e := d.MMIODevice.Write(a, s, v)
	if e == nil {
		d.observe(MMIOAccess{a, v, s, true})
	}
	return e
}

type nativeDisk struct{ *blockstar.OverlayDevice }

func (d nativeDisk) Size() int64 { return d.Geometry().Size }

func (n *NativeExecution) AttachNVMe(m *Machine, handle uint64, config hypervisor.NVMePCIConfiguration) error {
	endpoint, ok := m.blockHandles[handle]
	if !ok || endpoint.Offset != 0 || endpoint.Size != m.diskStores[endpoint.Store].overlay.Geometry().Size {
		return fmt.Errorf("native NVMe requires a whole-disk firmware handle")
	}
	if len(n.devices) != 0 {
		return fmt.Errorf("native PCI bus already attached")
	}
	store, err := m.diskStores[endpoint.Store].clone()
	if err != nil {
		return err
	}
	dev, err := n.cpu.NewNVMePCI(config, nativeDisk{store.overlay})
	if err != nil {
		return err
	}
	n.devices = append(n.devices, observedMMIO{dev, n})
	n.Disk = store.overlay
	n.pci = dev
	return nil
}

type NativeModule struct {
	Name       string
	Base, Size uint64
}

type runtimeRange struct{ physical, virtual, size uint64 }

func (m *Machine) StartNative(ctx context.Context) (*NativeExecution, error) {
	if m.memory == nil || !m.exited {
		return nil, fmt.Errorf("uefi: native continuation requires successful ExitBootServices")
	}
	s := hypervisor.ARM64State{System: map[uint16]uint64{}}
	for i := range s.X {
		s.X[i], _ = m.Register(fmt.Sprintf("x%d", i))
	}
	for i := range s.Q {
		s.Q[i], _ = m.processor.Vector(i)
	}
	s.PC, _ = m.Register("pc")
	nzcv, _ := m.Register("nzcv")
	daif, _ := m.Register("daif")
	el, _ := m.Register("current_el")
	if el != 4 {
		return nil, fmt.Errorf("uefi: native handoff requires EL1, got CurrentEL=%#x", el)
	}
	s.PState = nzcv | daif | 5
	for _, r := range []struct {
		name     string
		encoding uint16
	}{
		{"sp", 0xe208}, {"sctlr_el1", 0xc080}, {"ttbr0_el1", 0xc100}, {"ttbr1_el1", 0xc101},
		{"tcr_el1", 0xc102}, {"mair_el1", 0xc510}, {"vbar_el1", 0xc600}, {"cpacr_el1", 0xc082},
		{"tpidr_el0", 0xde82}, {"tpidrro_el0", 0xde83}, {"tpidr_el1", 0xc684},
	} {
		s.System[r.encoding], _ = m.Register(r.name)
	}
	backend, err := hypervisor.NewARM64(ctx)
	if err != nil {
		return nil, err
	}
	// With the native GIC, HVF enables its cycle-counter implementation when
	// PMUVer=1 is selected. Preserve its other debug feature fields.
	dfr, err := backend.SystemRegister(0xc028)
	if err != nil {
		_ = backend.Close()
		return nil, err
	}
	s.System[0xc028] = dfr&^uint64(0xf00) | 0x100
	ram, err := backend.MapRAM(m.ramBase, m.opts.Memory)
	if err == nil {
		err = m.ReadMemory(m.ramBase, ram)
	}
	if err == nil {
		err = backend.Restore(s)
	}
	if err == nil {
		err = backend.SetDebugExceptionTrapping(true)
	}
	if err != nil {
		_ = backend.Close()
		return nil, err
	}
	n := &NativeExecution{cpu: backend, ram: ram, base: m.ramBase, gates: map[uint16]string{}}
	n.Modules = map[uint64]NativeModule{}
	n.Counts = map[string]uint64{}
	fw := *m
	fw.processor = m.processor.Clone().(*arm64.CPU)
	fw.memory = nil
	fw.runtimeMemory = n
	fw.opts.Observe = nil
	fw.variables = maps.Clone(m.variables)
	for k, v := range fw.variables {
		v.Data = slices.Clone(v.Data)
		fw.variables[k] = v
	}
	n.firmware = &fw
	n.clockBase, n.clockFrequency, err = backend.Counter()
	if err != nil {
		_ = backend.Close()
		return nil, err
	}
	n.firmwareTicks, _ = m.Register("cntpct_el0")
	n.firmwareFrequency, _ = m.Register("cntfrq_el0")
	// Firmware gates were intercepted by the interpreter. In native execution
	// each becomes an identified HVC; the guest's runtime pointers stay valid.
	for addr, name := range m.services {
		id := uint16((addr-m.firstService)/4 + 1)
		n.gates[id] = name
		binary.LittleEndian.PutUint32(ram[addr-m.ramBase:], 0xd4000002|uint32(id)<<5)
	}
	return n, nil
}

func (n *NativeExecution) Run(ctx context.Context) (hypervisor.Exit, error) {
	for {
		ex, err := n.cpu.Run(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				pc, readErr := n.cpu.Register(31)
				return hypervisor.Exit{PC: pc}, readErr
			}
			return ex, err
		}
		n.Counts[fmt.Sprintf("exit_%d_ec_%x", ex.Reason, ex.Syndrome>>26)]++
		// Device completions cancel hv_vcpu_run to publish an interrupt. They
		// are internal wakeups, distinct from the caller's execution deadline.
		if ex.Reason == 0 && ctx.Err() == nil {
			continue
		}
		if ex.Reason == 1 && ex.Syndrome>>26 == 0x16 {
			if name, ok := n.gates[uint16(ex.Syndrome)]; ok {
				if err := n.runtimeCall(name); err != nil {
					return ex, err
				}
				continue
			}
			if uint16(ex.Syndrome) == 0 {
				shutdown, err := n.cpu.HandlePSCI()
				if err != nil {
					return ex, err
				}
				if !shutdown {
					continue
				}
			}
		}
		if ex.Reason == 1 && ex.Syndrome>>26 == 0x18 {
			handled, err := n.cpu.HandleSystemInstruction(ex.Syndrome)
			if err != nil {
				return ex, err
			}
			if handled {
				continue
			}
		}
		handledMMIO := false
		for _, device := range n.devices {
			handled, err := n.cpu.EmulateMMIO(ex, device)
			if err != nil {
				return ex, err
			}
			if handled {
				handledMMIO = true
				n.Counts["mmio"]++
				break
			}
		}
		if handledMMIO {
			continue
		}
		if n.WindowsDebug && ex.Reason == 1 && ex.Syndrome>>26 == 0x3c && uint16(ex.Syndrome) == 0xf002 {
			handled, err := n.debugSymbols(ex.PC)
			if err != nil {
				return ex, err
			}
			if handled {
				continue
			}
		}
		if n.WindowsDebug && ex.Reason == 1 && ex.Syndrome>>26 == 0x3c && uint16(ex.Syndrome) == 0xf004 {
			if err := n.cpu.DeliverDebugException(ex); err != nil {
				return ex, err
			}
			continue
		}
		return ex, nil
	}
}

func (n *NativeExecution) debugSymbols(pc uint64) (bool, error) {
	service, err := n.cpu.Register(16)
	if err != nil {
		return false, err
	}
	if service != 1 && service != 3 && service != 4 {
		return false, nil
	}
	var instructions [12]byte
	if err := n.ReadVirtualMemory(pc, instructions[:]); err != nil {
		return false, err
	}
	if binary.LittleEndian.Uint32(instructions[:]) != 0xd43e0040 || binary.LittleEndian.Uint32(instructions[4:]) != 0xd43e0000 || binary.LittleEndian.Uint32(instructions[8:]) != 0xd65f03c0 {
		return false, nil
	}
	arg0, err := n.cpu.Register(0)
	if err != nil {
		return false, err
	}
	arg1, err := n.cpu.Register(1)
	if err != nil {
		return false, err
	}
	if service == 1 {
		if arg1 > 4096 || n.consoleBytes+arg1 > 65536 {
			return false, fmt.Errorf("native debug output observation limit reached")
		}
		message := make([]byte, arg1)
		if err := n.ReadVirtualMemory(arg0, message); err != nil {
			return false, err
		}
		n.Console = append(n.Console, string(message))
		n.consoleBytes += arg1
		if err := n.cpu.SetRegister(0, 0); err != nil {
			return false, err
		}
		return true, n.cpu.SetRegister(31, pc+8)
	}
	var name [16]byte
	var info [24]byte
	if err := n.ReadVirtualMemory(arg0, name[:]); err != nil {
		return false, err
	}
	if err := n.ReadVirtualMemory(arg1, info[:]); err != nil {
		return false, err
	}
	length := binary.LittleEndian.Uint16(name[:])
	if length > 4096 {
		return false, fmt.Errorf("debug symbol name exceeds 4096 bytes")
	}
	text := make([]byte, length)
	if err := n.ReadVirtualMemory(binary.LittleEndian.Uint64(name[8:]), text); err != nil {
		return false, err
	}
	base := binary.LittleEndian.Uint64(info[:])
	if service == 4 {
		delete(n.Modules, base)
	} else {
		if len(n.Modules) >= 4096 {
			return false, fmt.Errorf("native module observation limit reached")
		}
		n.Modules[base] = NativeModule{string(text), base, uint64(binary.LittleEndian.Uint32(info[20:]))}
	}
	return true, n.cpu.SetRegister(31, pc+8)
}

func (n *NativeExecution) CheckMemory(a uint64, size int, _ cpu.Access) error {
	if size < 0 || a < n.base || a-n.base > uint64(len(n.ram)) || uint64(size) > uint64(len(n.ram))-(a-n.base) {
		return fmt.Errorf("native physical memory access %#x+%d outside RAM", a, size)
	}
	return nil
}
func (n *NativeExecution) ReadMemory(a uint64, b []byte, access cpu.Access) error {
	if err := n.CheckMemory(a, len(b), access); err != nil {
		return err
	}
	copy(b, n.ram[a-n.base:])
	return nil
}
func (n *NativeExecution) WriteMemory(a uint64, b []byte) error {
	if err := n.CheckMemory(a, len(b), cpu.Write); err != nil {
		return err
	}
	copy(n.ram[a-n.base:], b)
	return nil
}

func (n *NativeExecution) runtimeCall(name string) error {
	fw := n.firmware
	if err := n.syncTranslation(); err != nil {
		return err
	}
	var args [8]uint64
	for i := range args {
		value, err := n.cpu.Register(uint32(i))
		if err != nil {
			return err
		}
		args[i] = value
	}
	status := unsupported
	if name == "GetTime" {
		now, _, err := n.cpu.Counter()
		if err != nil {
			return err
		}
		delta := now - n.clockBase
		ticks := n.firmwareTicks + (delta/n.clockFrequency)*n.firmwareFrequency + (delta%n.clockFrequency)*n.firmwareFrequency/n.clockFrequency
		if err := fw.processor.SetRegister("cntpct_el0", ticks); err != nil {
			return err
		}
	}
	switch name {
	case "SetVirtualAddressMap":
		status = n.setVirtualAddressMap(args)
	case "GetTime", "GetVariable", "SetVariable", "GetNextVariableName", "QueryVariableInfo":
		var supported bool
		status, supported = fw.dispatch(name, args)
		if !supported {
			return fmt.Errorf("unimplemented native runtime service %s", name)
		}
	default:
		return fmt.Errorf("unimplemented native runtime service %s args=%#x", name, args)
	}
	if fw.err != nil {
		return fmt.Errorf("native runtime %s: %w", name, fw.err)
	}
	lr, err := n.cpu.Register(30)
	if err != nil {
		return err
	}
	if err := n.cpu.SetRegister(0, status); err != nil {
		return err
	}
	return n.cpu.SetRegister(31, lr)
}

func (n *NativeExecution) syncTranslation() error {
	fw := n.firmware
	for name, encoding := range map[string]uint16{"sctlr_el1": 0xc080, "tcr_el1": 0xc102, "ttbr0_el1": 0xc100, "ttbr1_el1": 0xc101, "mair_el1": 0xc510} {
		value, err := n.cpu.SystemRegister(encoding)
		if err != nil {
			return err
		}
		_ = fw.processor.SetRegister(name, value)
	}
	return nil
}

func (n *NativeExecution) ReadVirtualMemory(a uint64, b []byte) error {
	if err := n.syncTranslation(); err != nil {
		return err
	}
	return n.firmware.processor.VirtualMemory(n).ReadMemory(a, b, cpu.Read)
}

func (n *NativeExecution) setVirtualAddressMap(a [8]uint64) uint64 {
	if n.virtualMap != nil || a[1] < 40 || a[1] > 4096 || a[0] == 0 || a[0] > 1<<20 || a[0]%a[1] != 0 || a[2] != 1 {
		return invalidParameter
	}
	data := n.firmware.get(a[3], a[0])
	if n.firmware.err != nil {
		return invalidParameter
	}
	var ranges []runtimeRange
	for offset := uint64(0); offset < a[0]; offset += a[1] {
		d := data[offset:]
		p := binary.LittleEndian.Uint64(d[8:])
		v := binary.LittleEndian.Uint64(d[16:])
		pages := binary.LittleEndian.Uint64(d[24:])
		attr := binary.LittleEndian.Uint64(d[32:])
		if attr>>63 == 0 {
			continue
		}
		if pages == 0 || pages > ^uint64(0)/4096 || p&4095 != 0 || v&4095 != 0 {
			return invalidParameter
		}
		size := pages * 4096
		if p+size < p || v+size < v {
			return invalidParameter
		}
		for _, r := range ranges {
			if p < r.physical+r.size && r.physical < p+size {
				return invalidParameter
			}
		}
		ranges = append(ranges, runtimeRange{p, v, size})
	}
	convert := func(p uint64) (uint64, bool) {
		for _, r := range ranges {
			if p >= r.physical && p-r.physical < r.size {
				return r.virtual + p - r.physical, true
			}
		}
		return 0, false
	}
	runtime := n.ram[0x500 : 0x500+136]
	updated := slices.Clone(runtime)
	for offset := 24; offset < 136; offset += 8 {
		p := binary.LittleEndian.Uint64(runtime[offset:])
		v, ok := convert(p)
		if !ok {
			return notFound
		}
		binary.LittleEndian.PutUint64(updated[offset:], v)
	}
	// The system table address is configurable within the firmware layout.
	table := n.ram[n.firmware.systemTable-n.base : n.firmware.systemTable-n.base+120]
	system := slices.Clone(table)
	for _, offset := range []int{24, 88, 112} {
		p := binary.LittleEndian.Uint64(system[offset:])
		if p == 0 {
			continue
		}
		v, ok := convert(p)
		if !ok {
			return notFound
		}
		binary.LittleEndian.PutUint64(system[offset:], v)
	}
	binary.LittleEndian.PutUint32(updated[16:], 0)
	binary.LittleEndian.PutUint32(updated[16:], crc32.ChecksumIEEE(updated))
	binary.LittleEndian.PutUint32(system[16:], 0)
	binary.LittleEndian.PutUint32(system[16:], crc32.ChecksumIEEE(system))
	copy(runtime, updated)
	copy(table, system)
	n.virtualMap = ranges
	return 0
}
func (n *NativeExecution) Register(name string) (uint64, error) {
	if len(name) > 1 && name[0] == 'x' {
		i, err := strconv.Atoi(name[1:])
		if err == nil && i >= 0 && i < 31 {
			return n.cpu.Register(uint32(i))
		}
	}
	if name == "pc" {
		return n.cpu.Register(31)
	}
	if name == "pstate" {
		return n.cpu.Register(34)
	}
	regs := map[string]uint16{"cntv_ctl_el0": 0xdf19, "cntv_cval_el0": 0xdf1a, "cntp_ctl_el0": 0xdf11, "cntp_cval_el0": 0xdf12, "cntfrq_el0": 0xdf00, "esr_el1": 0xc290, "elr_el1": 0xc201, "spsr_el1": 0xc200, "far_el1": 0xc300, "sctlr_el1": 0xc080, "tcr_el1": 0xc102, "ttbr0_el1": 0xc100, "ttbr1_el1": 0xc101, "sp": 0xe208}
	if r, ok := regs[name]; ok {
		return n.cpu.SystemRegister(r)
	}
	return 0, fmt.Errorf("unknown native register %q", name)
}
func (n *NativeExecution) Close() error {
	if n.cpu == nil {
		return nil
	}
	err := n.cpu.Close()
	n.cpu = nil
	n.ram = nil
	return err
}
