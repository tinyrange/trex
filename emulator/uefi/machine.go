// Package uefi executes an AArch64 EFI image against a portable firmware
// environment. It stops at a validated ExitBootServices transition. It does
// not yet implement a hardware-accelerated continuation backend.
package uefi

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"slices"
	"sort"
	"time"
	"unicode/utf16"

	"github.com/tinyrange/trex/emulator/arm64"
	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/emulator/peimage"
	"github.com/tinyrange/trex/storage"
	"github.com/tinyrange/trex/windows/guid"
)

const (
	ramBase          = uint64(0x40000000)
	page             = uint64(4096)
	efiError         = uint64(1) << 63
	invalidParameter = efiError | 2
	unsupported      = efiError | 3
	bufferTooSmall   = efiError | 5
	notReady         = efiError | 6
	outOfResources   = efiError | 9
	notFound         = efiError | 14
	loadedImageGUID  = "{5B1B31A1-9562-11D2-8E3F-00A0C969723B}"
	devicePathGUID   = "{09576E91-6D3F-11D2-8E39-00A0C969723B}"
)

// Event is a bounded observation point. Firmware output and calls are reported
// to the caller instead of writing to host consoles or files.
type Event struct {
	Address, Size    uint64
	Access           cpu.Access
	Data             []byte
	Kind, Name, Text string
	PC               uint64
	Args             [8]uint64
}
type Options struct {
	// TimeUnix is the virtual wall-clock epoch. The ARM generic counter
	// advances time; the core never reads the host wall clock.
	TimeUnix   int64
	Memory     uint64
	MemoryBase uint64
	ImageBase  uint64
	StackSize  uint64
	ImagePath  string
	Registers  map[string]uint64
	// DevicePath identifies the volume from which the EFI image was loaded.
	// It is a serialized EFI_DEVICE_PATH_PROTOCOL, including its end node.
	DevicePath []byte
	// Observe runs synchronously. It may inspect state and register verified
	// rewrites, but must not re-enter Run or change guest CPU/RAM. Returning an
	// error stops execution, for example when an observation budget fills.
	Observe func(Event) error
	// EventKinds optionally filters observation before constructing records.
	// Nil observes all kinds; an empty non-nil slice observes none.
	EventKinds []string
}
type allocation struct {
	Base, Pages uint64
	Type        uint32
}
type Result struct {
	Reason, Detail    string
	Steps, PC, MapKey uint64
	Service           string
	Args              [8]uint64
	Trace             []uint64
}
type Machine struct {
	rewrites                                           map[uint64]Rewrite
	rewriteCode                                        [4096]byte
	rewriteFilter                                      [4096]bool
	bulkBuffer                                         [65536]byte
	protocolOpens                                      map[protocolOpen]uint32
	diskStores                                         []diskStore
	blockHandles, blockInterfaces                      map[uint64]blockEndpoint
	configuration                                      map[[16]byte]uint64
	observation                                        *observation
	variables                                          map[variableKey]Variable
	ramBase                                            uint64
	processor                                          *arm64.CPU
	memory                                             *cpu.AddressSpace
	opts                                               Options
	allocations                                        []allocation
	mapKey                                             uint64
	services                                           map[uint64]string
	protocols                                          map[uint64]map[string]uint64
	nextService                                        uint64
	firstService                                       uint64
	systemTable, bootTable, imageHandle, returnAddress uint64
	err                                                error
	exited                                             bool
	steps                                              uint64
}

// New loads and relocates a caller-owned EFI PE image. RAM and EFI addresses
// are guest physical addresses and have no relationship to host addresses.
func New(image storage.Reader, opts Options) (*Machine, error) {
	opts.EventKinds = slices.Clone(opts.EventKinds)
	if opts.MemoryBase == 0 {
		opts.MemoryBase = ramBase
	}
	if opts.StackSize == 0 {
		opts.StackSize = 1 << 20
	}
	if opts.ImagePath == "" {
		opts.ImagePath = "\\EFI\\Boot\\BootAA64.efi"
	}
	if opts.Memory == 0 {
		opts.Memory = 256 << 20
	}
	if opts.Memory < 16<<20 || opts.Memory > 2<<30 || opts.Memory%page != 0 {
		return nil, fmt.Errorf("uefi: memory must be page aligned, between 16 MiB and 2 GiB")
	}
	if opts.MemoryBase%page != 0 || opts.MemoryBase > ^uint64(0)-opts.Memory || opts.StackSize%page != 0 || opts.StackSize > opts.Memory {
		return nil, fmt.Errorf("uefi: invalid RAM/stack layout")
	}
	if image.Size() < 0 || uint64(image.Size()) > opts.Memory {
		return nil, fmt.Errorf("uefi: image exceeds memory budget")
	}
	data := make([]byte, int(image.Size()))
	if _, err := io.ReadFull(io.NewSectionReader(image, 0, image.Size()), data); err != nil {
		return nil, err
	}
	pe, err := peimage.Parse(data, opts.Memory)
	if err != nil {
		return nil, err
	}
	if pe.Architecture.Name != "arm64" {
		return nil, fmt.Errorf("uefi: expected ARM64 EFI image, got %s", pe.Architecture.Name)
	}
	m := &Machine{ramBase: opts.MemoryBase, processor: arm64.New(), memory: cpu.NewAddressSpace(opts.Memory), opts: opts, mapKey: 1, services: map[uint64]string{}, protocols: map[uint64]map[string]uint64{}, nextService: opts.MemoryBase + 0x1000}
	if err := m.memory.Map(m.ramBase, make([]byte, int(opts.Memory)), cpu.Read|cpu.Write|cpu.Execute); err != nil {
		return nil, err
	}
	m.variables = map[variableKey]Variable{}
	m.protocolOpens = map[protocolOpen]uint32{}
	m.blockHandles = map[uint64]blockEndpoint{}
	m.blockInterfaces = map[uint64]blockEndpoint{}
	m.configuration = map[[16]byte]uint64{}
	m.allocations = []allocation{{m.ramBase, 16, 6}} // runtime firmware tables and service gates
	m.systemTable = m.ramBase + 0x100
	m.bootTable = m.ramBase + 0x200
	m.imageHandle = m.ramBase + 0x800
	m.returnAddress = m.ramBase + 0x900
	m.tables()
	kind := uint64(0)
	if opts.ImageBase != 0 {
		kind = 2
	}
	base := m.allocate(kind, 1, uint64(len(pe.Data)+4095)/page, opts.ImageBase)
	if base == 0 {
		return nil, fmt.Errorf("uefi: insufficient image memory")
	}
	if err := peimage.Relocate(pe.Data, pe.Directories[5], pe.PreferredBase, base, 8); err != nil {
		return nil, err
	}
	m.put(base, pe.Data)
	stack := m.allocate(0, 2, opts.StackSize/page, 0)
	if stack == 0 {
		return nil, fmt.Errorf("uefi: insufficient stack memory")
	}
	loaded := m.ramBase + 0xa00
	m.u32(loaded, 0x1000)
	m.u64(loaded+16, m.systemTable)
	m.u64(loaded+24, m.ramBase+0xb00)
	// LoadedImage.FilePath is relative to DeviceHandle's volume path.
	path := utf16.Encode([]rune(opts.ImagePath))
	if len(path) > 1024 {
		return nil, fmt.Errorf("uefi: image path exceeds 1024 UTF-16 units")
	}
	filePath := make([]byte, 4+2*(len(path)+1)+4)
	filePath[0], filePath[1] = 4, 4
	binary.LittleEndian.PutUint16(filePath[2:], uint16(len(filePath)-4))
	for j, v := range path {
		binary.LittleEndian.PutUint16(filePath[4+j*2:], v)
	}
	copy(filePath[len(filePath)-4:], []byte{0x7f, 0xff, 4, 0})
	m.put(m.ramBase+0x2000, filePath)
	m.u64(loaded+32, m.ramBase+0x2000)
	m.u64(loaded+64, base)
	m.u64(loaded+72, uint64(len(pe.Data)))
	m.u32(loaded+80, 1)
	m.u32(loaded+84, 2)
	m.protocols[m.imageHandle] = map[string]uint64{loadedImageGUID: loaded}
	if len(opts.DevicePath) != 0 {
		p := m.allocate(0, 4, (uint64(len(opts.DevicePath))+4095)/page, 0)
		if p == 0 {
			return nil, fmt.Errorf("uefi: insufficient device path memory")
		}
		m.put(p, opts.DevicePath)
		m.protocols[m.ramBase+0xb00] = map[string]uint64{devicePathGUID: p}
	}
	m.processor.SetPC(base + uint64(pe.EntryRVA))
	m.processor.SetRegister("current_el", 4)
	m.processor.SetRegister("sp", stack+opts.StackSize-16)
	m.processor.SetRegister("x0", m.imageHandle)
	m.processor.SetRegister("x1", m.systemTable)
	m.processor.SetRegister("lr", m.returnAddress)
	// AArch64 UEFI enters with the MMU enabled and RAM identity-mapped.
	root := m.ramBase + 0x4000
	directories := map[uint64]uint64{}
	for p := m.ramBase & ^uint64((1<<30)-1); p < m.ramBase+opts.Memory; p += 1 << 30 {
		index := p >> 39 & 511
		directory := directories[index]
		if directory == 0 {
			directory = m.ramBase + 0x5000 + uint64(len(directories))*page
			directories[index] = directory
			m.u64(root+index*8, directory|3)
		}
		m.u64(directory+(p>>30&511)*8, p|0x701)
	}
	m.processor.SetRegister("ttbr0_el1", root)
	m.processor.SetRegister("tcr_el1", 16|16<<16|2<<30|3<<12|1<<10|1<<8|3<<28|1<<26|1<<24|5<<32)
	m.processor.SetRegister("mair_el1", 255)
	m.processor.SetRegister("sctlr_el1", 0x30d01805)
	registerNames := make([]string, 0, len(opts.Registers))
	for name := range opts.Registers {
		registerNames = append(registerNames, name)
	}
	sort.Strings(registerNames)
	for _, name := range registerNames {
		if err := m.processor.SetRegister(name, opts.Registers[name]); err != nil {
			return nil, err
		}
	}
	if m.err != nil {
		return nil, m.err
	}
	return m, nil
}

func (m *Machine) put(p uint64, b []byte) {
	if m.err == nil {
		m.err = m.processor.VirtualMemory(m.executionMemory()).WriteMemory(p, b)
	}
}
func (m *Machine) get(p, n uint64) []byte {
	if n > m.opts.Memory {
		m.err = fmt.Errorf("uefi: read exceeds memory budget")
		return nil
	}
	b := make([]byte, int(n))
	if m.err == nil {
		m.err = m.processor.VirtualMemory(m.executionMemory()).ReadMemory(p, b, cpu.Read)
	}
	return b
}
func (m *Machine) u64(p, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	m.put(p, b[:])
}
func (m *Machine) u32(p uint64, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	m.put(p, b[:])
}
func (m *Machine) read64(p uint64) uint64 {
	b := m.get(p, 8)
	if len(b) != 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}
func (m *Machine) text(p uint64) string {
	var units []uint16
	for j := uint64(0); j < 32768; j++ {
		b := m.get(p+2*j, 2)
		if m.err != nil {
			return ""
		}
		v := binary.LittleEndian.Uint16(b)
		if v == 0 {
			return string(utf16.Decode(units))
		}
		units = append(units, v)
	}
	m.err = fmt.Errorf("uefi: unterminated UTF-16 string")
	return ""
}
func (m *Machine) gate(name string) uint64 {
	v := m.nextService
	if len(m.services) == 0 {
		m.firstService = v
	}
	m.nextService += 4
	m.services[v] = name
	return v
}
func (m *Machine) table(p, signature uint64, size uint32) {
	m.u64(p, signature)
	m.u32(p+8, 0x20064)
	m.u32(p+12, size)
}
func (m *Machine) checksum(p uint64, n uint32) {
	m.u32(p+16, 0)
	m.u32(p+16, crc32.ChecksumIEEE(m.get(p, uint64(n))))
}
func (m *Machine) tables() {
	m.table(m.systemTable, 0x5453595320494249, 120)
	m.u64(m.systemTable+24, m.ramBase+0xc00)
	m.put(m.ramBase+0xc00, []byte{'T', 0, 'i', 0, 'n', 0, 'y', 0, 'R', 0, 'a', 0, 'n', 0, 'g', 0, 'e', 0, 'X', 0, 0, 0})
	m.u32(m.systemTable+32, 1)
	console := m.ramBase + 0xd00
	input := m.ramBase + 0xe00
	runtime := m.ramBase + 0x500
	for j, name := range []string{"Text.Reset", "Text.OutputString", "Text.TestString", "Text.QueryMode", "Text.SetMode", "Text.SetAttribute", "Text.ClearScreen", "Text.SetCursorPosition", "Text.EnableCursor"} {
		m.u64(console+uint64(j)*8, m.gate(name))
	}
	m.u64(console+72, console+80)
	m.u32(console+80, 1)
	m.u32(console+88, 7)
	m.u32(console+100, 1)
	m.u64(input, m.gate("Input.Reset"))
	m.u64(input+8, m.gate("Input.ReadKeyStroke"))
	m.u64(input+16, m.ramBase+0xf00)
	m.u64(m.systemTable+40, input)
	m.u64(m.systemTable+48, input)
	m.u64(m.systemTable+56, console)
	m.u64(m.systemTable+64, console)
	m.u64(m.systemTable+72, console)
	m.u64(m.systemTable+80, console)
	m.u64(m.systemTable+88, runtime)
	m.u64(m.systemTable+96, m.bootTable)
	m.table(runtime, 0x56524553544e5552, 136)
	for j, name := range []string{"GetTime", "SetTime", "GetWakeupTime", "SetWakeupTime", "SetVirtualAddressMap", "ConvertPointer", "GetVariable", "GetNextVariableName", "SetVariable", "GetNextHighMonotonicCount", "ResetSystem", "UpdateCapsule", "QueryCapsuleCapabilities", "QueryVariableInfo"} {
		m.u64(runtime+24+uint64(j)*8, m.gate(name))
	}
	m.checksum(runtime, 136)
	names := []string{"RaiseTPL", "RestoreTPL", "AllocatePages", "FreePages", "GetMemoryMap", "AllocatePool", "FreePool", "CreateEvent", "SetTimer", "WaitForEvent", "SignalEvent", "CloseEvent", "CheckEvent", "InstallProtocolInterface", "ReinstallProtocolInterface", "UninstallProtocolInterface", "HandleProtocol", "Reserved", "RegisterProtocolNotify", "LocateHandle", "LocateDevicePath", "InstallConfigurationTable", "LoadImage", "StartImage", "Exit", "UnloadImage", "ExitBootServices", "GetNextMonotonicCount", "Stall", "SetWatchdogTimer", "ConnectController", "DisconnectController", "OpenProtocol", "CloseProtocol", "OpenProtocolInformation", "ProtocolsPerHandle", "LocateHandleBuffer", "LocateProtocol", "InstallMultipleProtocolInterfaces", "UninstallMultipleProtocolInterfaces", "CalculateCrc32", "CopyMem", "SetMem", "CreateEventEx"}
	m.table(m.bootTable, 0x56524553544f4f42, uint32(24+len(names)*8))
	for j, name := range names {
		if name != "Reserved" {
			m.u64(m.bootTable+24+uint64(j)*8, m.gate(name))
		}
	}
	m.checksum(m.bootTable, uint32(24+len(names)*8))
	m.checksum(m.systemTable, 120)
}

func (m *Machine) allocate(kind, typ, pages, address uint64) uint64 {
	if pages == 0 || pages > m.opts.Memory/page || kind > 2 || typ > 14 {
		return 0
	}
	size := pages * page
	start := m.ramBase
	sort.Slice(m.allocations, func(i, j int) bool { return m.allocations[i].Base < m.allocations[j].Base })
	var candidates []uint64
	for _, a := range append(append([]allocation(nil), m.allocations...), allocation{Base: m.ramBase + m.opts.Memory}) {
		end := a.Base
		if end >= start && end-start >= size {
			p := start
			if kind == 2 {
				p = address
			}
			if kind == 1 {
				limit := end
				if address != ^uint64(0) && address+1 < limit {
					limit = address + 1
				}
				if limit >= size {
					p = (limit - size) &^ (page - 1)
				} else {
					p = 0
				}
			}
			if p >= start && p <= end-size && p%page == 0 {
				candidates = append(candidates, p)
			}
		}
		start = a.Base + a.Pages*page
	}
	if len(candidates) == 0 {
		return 0
	}
	p := candidates[0]
	if kind == 1 {
		p = candidates[len(candidates)-1]
	}
	m.allocations = append(m.allocations, allocation{p, pages, uint32(typ)})
	m.mapKey++
	return p
}
func (m *Machine) free(p, pages uint64) bool {
	if p%page != 0 || pages == 0 || pages > m.opts.Memory/page || p < m.ramBase+16*page || p > m.ramBase+m.opts.Memory-pages*page {
		return false
	}
	end := p + pages*page
	allocs := slices.Clone(m.allocations)
	sort.Slice(allocs, func(i, j int) bool { return allocs[i].Base < allocs[j].Base })
	cursor := p
	for _, a := range allocs {
		if a.Base+a.Pages*page <= cursor {
			continue
		}
		if a.Base > cursor {
			break
		}
		cursor = min(end, a.Base+a.Pages*page)
		if cursor == end {
			break
		}
	}
	if cursor != end {
		return false
	}
	var result []allocation
	for _, a := range allocs {
		limit := a.Base + a.Pages*page
		if limit <= p || a.Base >= end {
			result = append(result, a)
			continue
		}
		if a.Base < p {
			result = append(result, allocation{a.Base, (p - a.Base) / page, a.Type})
		}
		if limit > end {
			result = append(result, allocation{end, (limit - end) / page, a.Type})
		}
	}
	m.allocations = result
	m.mapKey++
	return true
}
func (m *Machine) descriptors() []byte {
	allocs := append([]allocation(nil), m.allocations...)
	sort.Slice(allocs, func(i, j int) bool { return allocs[i].Base < allocs[j].Base })
	var all []allocation
	start := m.ramBase
	for _, a := range allocs {
		if a.Base > start {
			all = append(all, allocation{start, (a.Base - start) / page, 7})
		}
		all = append(all, a)
		start = a.Base + a.Pages*page
	}
	if start < m.ramBase+m.opts.Memory {
		all = append(all, allocation{start, (m.ramBase + m.opts.Memory - start) / page, 7})
	}
	b := make([]byte, len(all)*40)
	for j, a := range all {
		v := b[j*40:]
		binary.LittleEndian.PutUint32(v, a.Type)
		binary.LittleEndian.PutUint64(v[8:], a.Base)
		binary.LittleEndian.PutUint64(v[24:], a.Pages)
		attr := uint64(8)
		if a.Type == 5 || a.Type == 6 {
			attr |= 1 << 63
		}
		binary.LittleEndian.PutUint64(v[32:], attr)
	}
	return b
}
func (m *Machine) args() [8]uint64 {
	var a [8]uint64
	for j := range a {
		a[j], _ = m.processor.Register(fmt.Sprintf("x%d", j))
	}
	return a
}
func (m *Machine) emit(e Event) {
	if m.err == nil && m.observes(e.Kind) {
		m.err = m.opts.Observe(e)
	}
}

func (m *Machine) observes(kind string) bool {
	return m.opts.Observe != nil && (m.opts.EventKinds == nil || slices.Contains(m.opts.EventKinds, kind))
}

// Run is resumable after a step budget or unsupported instruction/service.
// ExitBootServices succeeds only with the current map key and loaded image.
func (m *Machine) Run(ctx context.Context, budget uint64) Result {
	return m.RunWithOptions(ctx, RunOptions{Steps: budget})
}
func (m *Machine) RunWithOptions(ctx context.Context, opts RunOptions) Result {
	var trace []uint64
	cursor := 0
	result := func(reason, detail, service string) Result {
		ordered := append(slices.Clone(trace[cursor:]), trace[:cursor]...)
		return Result{Reason: reason, Detail: detail, Steps: m.steps, PC: m.processor.PC(), MapKey: m.mapKey, Service: service, Args: m.args(), Trace: ordered}
	}
	if opts.TraceLimit < 0 || opts.TraceLimit > 100000 {
		return result("invalid_options", "trace limit must be between 0 and 100000", "")
	}
	if opts.Timeout < 0 || opts.Timeout > 0 && opts.Clock == nil {
		return result("invalid_options", "timeout requires a caller-supplied monotonic clock", "")
	}
	started := time.Duration(0)
	if opts.Timeout > 0 {
		started = opts.Clock.Now()
	}
	if m.memory == nil {
		return result("closed", "", "")
	}
	if m.observation != nil {
		return result("invalid_options", "run is already active", "")
	}
	for _, w := range opts.Watches {
		if w.Size == 0 || w.Address > ^uint64(0)-w.Size || w.Access == 0 || w.Access & ^(cpu.Read|cpu.Write|cpu.Execute) != 0 {
			return result("invalid_options", "invalid memory watch", "")
		}
	}
	m.observation = &observation{watches: slices.Clone(opts.Watches)}
	defer func() { m.observation = nil }()
	previousCacheSetting := m.processor.DisableTranslationCache
	previousDecodeSetting := m.processor.DisableDecodeCache
	m.processor.DisableTranslationCache = opts.DisableTranslationCache
	m.processor.DisableDecodeCache = opts.DisableDecodeCache
	defer func() { m.processor.DisableTranslationCache = previousCacheSetting }()
	defer func() { m.processor.DisableDecodeCache = previousDecodeSetting }()
	if m.exited {
		return result("exit_boot_services", "", "")
	}
	executionMemory := m.executionMemory()
	canAccelerate := !opts.DisableAcceleration && opts.TraceLimit == 0 && len(opts.Watches) == 0
	for j := uint64(0); j < opts.Steps; j++ {
		if j&1023 == 0 {
			if opts.Timeout > 0 && opts.Clock.Now()-started >= opts.Timeout {
				return result("timeout", "", "")
			}
			if err := ctx.Err(); err != nil {
				return result("cancelled", err.Error(), "")
			}
		}
		pc := m.processor.PC()
		if opts.SampleInterval != 0 && j%opts.SampleInterval == 0 {
			m.emit(Event{Kind: "sample", PC: pc})
			if m.err != nil {
				return result("observation_error", m.err.Error(), "")
			}
		}
		if slices.Contains(opts.StopPCs, pc) {
			return result("address_stop", "", "")
		}
		if opts.TraceLimit > 0 {
			if len(trace) < opts.TraceLimit {
				trace = append(trace, pc)
			} else {
				trace[cursor] = pc
				cursor = (cursor + 1) % opts.TraceLimit
			}
		}
		if pc == m.returnAddress {
			return result("image_returned", fmt.Sprintf("EFI status %#x", m.args()[0]), "")
		}
		var name string
		var service bool
		if pc >= m.firstService && pc < m.nextService {
			name, service = m.services[pc]
		}
		if service {
			if slices.Contains(opts.StopServices, name) {
				return result("service_stop", "", name)
			}
			a := m.args()
			text := ""
			if name == "HandleProtocol" || name == "OpenProtocol" || name == "LocateProtocol" || name == "LocateHandle" || name == "LocateHandleBuffer" {
				p := a[1]
				if name == "LocateProtocol" {
					p = a[0]
				}
				var raw [16]byte
				copy(raw[:], m.get(p, 16))
				text = guid.Format(raw)
			}
			m.emit(Event{Kind: "service", Name: name, PC: pc, Args: a, Text: text})
			status, supported := m.dispatch(name, a)
			if m.err != nil {
				return result("fault", m.err.Error(), name)
			}
			if !supported {
				return result("unsupported_service", "", name)
			}
			m.processor.SetRegister("x0", status)
			lr, _ := m.processor.Register("lr")
			m.processor.SetPC(lr)
			m.steps++
			if m.exited {
				return result("exit_boot_services", "", name)
			}
		} else {
			accelerated := false
			if canAccelerate && m.rewriteFilter[(pc>>2)&4095] {
				var err error
				accelerated, err = m.accelerate(pc, opts)
				if err != nil {
					return result("accelerator_fault", err.Error(), "")
				}
			}
			if !accelerated {
				_, err := m.processor.Step(executionMemory)
				if err != nil {
					return result("instruction_fault", err.Error(), "")
				}
			}
			m.steps++
		}
		if m.err != nil {
			return result("observation_error", m.err.Error(), "")
		}
		if m.observation.hit {
			return result("memory_watch", "", "")
		}
	}
	return result("budget", "", "")
}

func (m *Machine) dispatch(name string, a [8]uint64) (uint64, bool) {
	switch name {
	case "Block.Reset", "Block.Read", "Block.Write", "Block.Flush", "Disk.Read", "Disk.Write":
		return m.blockCall(name, a), true
	case "LocateHandle":
		return m.locateHandles(a, false)
	case "LocateHandleBuffer":
		return m.locateHandles(a, true)
	case "GetTime":
		if a[0] == 0 {
			return invalidParameter, true
		}
		ticks, _ := m.processor.Register("cntpct_el0")
		frequency, _ := m.processor.Register("cntfrq_el0")
		now := time.Unix(m.opts.TimeUnix+int64(ticks/frequency), int64(ticks%frequency)*1000000000/int64(frequency)).UTC()
		if now.Year() < 1900 || now.Year() > 9999 {
			return invalidParameter, true
		}
		var b [16]byte
		binary.LittleEndian.PutUint16(b[:], uint16(now.Year()))
		b[2] = byte(now.Month())
		b[3] = byte(now.Day())
		b[4] = byte(now.Hour())
		b[5] = byte(now.Minute())
		b[6] = byte(now.Second())
		binary.LittleEndian.PutUint32(b[8:], uint32(now.Nanosecond()))
		m.put(a[0], b[:])
		if a[1] != 0 {
			var caps [12]byte
			binary.LittleEndian.PutUint32(caps[:], uint32(frequency))
			m.put(a[1], caps[:])
		}
		return 0, true
	case "SetWatchdogTimer":
		if a[0] == 0 {
			return 0, true
		} // No watchdog is armed at entry.
		return 0, false
	case "InstallConfigurationTable":
		var raw [16]byte
		copy(raw[:], m.get(a[0], 16))
		return m.configurationTable(raw, a[1]), true
	case "AllocatePages":
		if a[0] > 2 || a[1] > 14 || a[2] == 0 {
			return invalidParameter, true
		}
		p := m.allocate(a[0], a[1], a[2], m.read64(a[3]))
		if p == 0 {
			return outOfResources, true
		}
		m.u64(a[3], p)
		return 0, true
	case "FreePages":
		if !m.free(a[0], a[1]) {
			return invalidParameter, true
		}
		return 0, true
	case "AllocatePool":
		if a[1] > m.opts.Memory {
			return outOfResources, true
		}
		p := m.allocate(0, a[0], max(1, (a[1]+4095)/page), 0)
		if p == 0 {
			return outOfResources, true
		}
		m.u64(a[2], p)
		return 0, true
	case "FreePool":
		for _, v := range m.allocations {
			if v.Base == a[0] && m.free(v.Base, v.Pages) {
				return 0, true
			}
		}
		return invalidParameter, true
	case "GetMemoryMap":
		b := m.descriptors()
		size := m.read64(a[0])
		m.u64(a[0], uint64(len(b)))
		m.u64(a[3], 40)
		m.u32(a[4], 1)
		if size < uint64(len(b)) {
			return bufferTooSmall, true
		}
		if a[1] == 0 {
			return invalidParameter, true
		}
		m.put(a[1], b)
		m.u64(a[2], m.mapKey)
		return 0, true
	case "ExitBootServices":
		if a[0] != m.imageHandle || a[1] != m.mapKey {
			return invalidParameter, true
		}
		m.exited = true
		return 0, true
	case "CopyMem":
		m.put(a[0], m.get(a[1], a[2]))
		return 0, true
	case "SetMem":
		if a[1] > m.opts.Memory {
			return invalidParameter, true
		}
		b := make([]byte, int(a[1]))
		for j := range b {
			b[j] = byte(a[2])
		}
		m.put(a[0], b)
		return 0, true
	case "CalculateCrc32":
		m.u32(a[2], crc32.ChecksumIEEE(m.get(a[0], a[1])))
		return 0, true
	case "OpenProtocol":
		return m.openProtocol(a), true
	case "CloseProtocol":
		return m.closeProtocol(a), true
	case "HandleProtocol":
		var raw [16]byte
		copy(raw[:], m.get(a[1], 16))
		p := m.protocols[a[0]][guid.Format(raw)]
		if p == 0 {
			return unsupported, true
		}
		m.u64(a[2], p)
		return 0, true
	case "LocateProtocol":
		var raw [16]byte
		copy(raw[:], m.get(a[0], 16))
		if handles := m.handles(guid.Format(raw)); len(handles) > 0 {
			m.u64(a[2], m.protocols[handles[0]][guid.Format(raw)])
			return 0, true
		}
		return notFound, true
	case "GetVariable":
		return m.getVariable(a), true
	case "SetVariable":
		return m.setVariable(a), true
	case "GetNextVariableName":
		if len(m.variables) != 0 {
			return 0, false
		}
		return notFound, true
	case "Input.ReadKeyStroke":
		if a[0] != m.ramBase+0xe00 || a[1] == 0 {
			return invalidParameter, true
		}
		return notReady, true
	case "Input.Reset":
		if a[0] != m.ramBase+0xe00 {
			return invalidParameter, true
		}
		// The input device currently has no queued keystrokes to discard.
		return 0, true
	case "Text.OutputString", "Text.TestString", "Text.QueryMode", "Text.Reset", "Text.SetMode", "Text.SetAttribute", "Text.ClearScreen", "Text.SetCursorPosition", "Text.EnableCursor":
		return m.textCall(name, a), true
	default:
		return 0, false
	}
}
