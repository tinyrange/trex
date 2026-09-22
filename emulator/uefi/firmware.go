package uefi

import (
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/emulator/peimage"
	"github.com/tinyrange/trex/storage"
)

// Firmware serves 64-bit EFI calls for a caller-owned CPU. Memory addresses
// are guest addresses; Gate emits a four-byte architecture-specific call gate.
// Clock supplies elapsed ticks and their frequency, never host wall time.
type FirmwareOptions struct {
	// PhysicalMemory accesses firmware tables after the caller changes its page tables.
	PhysicalMemory cpu.Memory
	Options
	Memory       cpu.Memory
	Stall        func(time.Duration) error
	Architecture string
	Gate         func(address uint64) []byte
	Clock        func() (ticks, frequency uint64)
}

type Firmware struct {
	physical   cpu.Memory
	virtualMap []runtimeRange
	stall      func(time.Duration) error
	graphics   *graphicsOutput
	machine    *Machine
	entry      FirmwareEntry
}
type FirmwareEntry struct{ PC, Stack, ImageHandle, SystemTable, ReturnAddress, DeviceHandle uint64 }

func NewFirmware(image storage.Reader, opts FirmwareOptions) (*Firmware, error) {
	if opts.PhysicalMemory == nil {
		opts.PhysicalMemory = opts.Memory
	}
	o := opts.Options
	o.EventKinds = slices.Clone(o.EventKinds)
	o.Reservations = slices.Clone(o.Reservations)
	if o.StackSize == 0 {
		o.StackSize = 1 << 20
	}
	if o.ImagePath == "" {
		o.ImagePath = "\\EFI\\Boot\\BootX64.efi"
	}
	if opts.Memory == nil || opts.Gate == nil || opts.Clock == nil || o.Memory < 16<<20 || o.Memory > 2<<30 || o.Memory%page != 0 || o.MemoryBase%page != 0 || o.MemoryBase > ^uint64(0)-o.Memory || o.StackSize%page != 0 || o.StackSize > o.Memory {
		return nil, fmt.Errorf("uefi: invalid external firmware memory or callbacks")
	}
	if image.Size() < 0 || uint64(image.Size()) > o.Memory {
		return nil, fmt.Errorf("uefi: image exceeds memory budget")
	}
	data := make([]byte, int(image.Size()))
	if _, err := io.ReadFull(io.NewSectionReader(image, 0, image.Size()), data); err != nil {
		return nil, err
	}
	pe, err := peimage.Parse(data, o.Memory)
	if err != nil {
		return nil, err
	}
	if pe.Architecture.PointerSize != 8 || pe.Architecture.Name != opts.Architecture {
		return nil, fmt.Errorf("uefi: expected %s EFI image, got %s", opts.Architecture, pe.Architecture.Name)
	}
	m := &Machine{ramBase: o.MemoryBase, opts: o, mapKey: 1, services: map[uint64]string{}, protocols: map[uint64]map[string]uint64{}, nextService: o.MemoryBase + 0x1000, firmwareMemory: opts.Memory, firmwareClock: opts.Clock}
	m.firmwareGate = func(address uint64) []byte {
		b := opts.Gate(address)
		if len(b) != 4 {
			m.err = fmt.Errorf("uefi: service gate must contain four bytes")
			return nil
		}
		return b
	}
	base, stack, err := m.loadImage(pe)
	if err != nil {
		return nil, err
	}
	m.put(m.returnAddress, m.firmwareGate(m.returnAddress))
	return &Firmware{machine: m, physical: opts.PhysicalMemory, stall: opts.Stall, entry: FirmwareEntry{base + uint64(pe.EntryRVA), stack + o.StackSize, m.imageHandle, m.systemTable, m.returnAddress, m.ramBase + 0xb00}}, m.err
}
func (f *Firmware) Entry() FirmwareEntry { return f.entry }
func (f *Firmware) Service(address uint64) (string, bool) {
	name, ok := f.machine.services[address]
	return name, ok
}
func (f *Firmware) Call(address uint64, args [10]uint64) (uint64, error) {
	m := f.machine
	name, ok := m.services[address]
	if !ok {
		return 0, fmt.Errorf("uefi: unknown call gate %#x", address)
	}
	m.firmwarePC = address
	m.emit(Event{Kind: "service", Name: name, PC: address, Args: [8]uint64(args[:8])})
	if name == "SetVirtualAddressMap" {
		return f.setVirtualAddressMap(args)
	}
	if name == "ConvertPointer" {
		if args[1] == 0 || args[0]&^uint64(1) != 0 {
			return invalidParameter, nil
		}
		p := m.read64(args[1])
		if p == 0 && args[0]&1 != 0 {
			return 0, m.err
		}
		v, ok := f.convertRuntimePointer(p)
		if !ok {
			return notFound, nil
		}
		m.u64(args[1], v)
		return 0, m.err
	}
	if name == "Stall" {
		if f.stall == nil || args[0] > uint64((1<<63-1)/int64(time.Microsecond)) {
			return unsupported, nil
		}
		return 0, f.stall(time.Duration(args[0]) * time.Microsecond)
	}
	if name == "GOP.QueryMode" || name == "GOP.SetMode" || name == "GOP.Blt" {
		return f.graphicsCall(name, args)
	}
	status, supported := m.dispatch(name, [8]uint64(args[:8]))
	if m.err != nil {
		return 0, fmt.Errorf("uefi %s: %w", name, m.err)
	}
	if !supported {
		return 0, fmt.Errorf("uefi: unsupported service %s args=%#x", name, args)
	}
	return status, nil
}
func (f *Firmware) ExitedBootServices() bool { return f.machine.exited }
func (f *Firmware) InstallConfigurationTable(identifier string, data []byte, memoryType uint32) (uint64, error) {
	return f.machine.InstallConfigurationTable(identifier, data, memoryType)
}

// AttachBlockDevice shares the caller's device, including its snapshot policy,
// with firmware and the eventual operating-system storage controller.
func (f *Firmware) AttachBlockDevice(device block.Device, opts BlockOptions) (uint64, error) {
	g := device.Geometry()
	if g.Size <= 0 || g.LogicalBlockSize == 0 || g.Size%int64(g.LogicalBlockSize) != 0 {
		return 0, fmt.Errorf("uefi: invalid block geometry")
	}
	m := f.machine
	index := len(m.diskStores)
	m.diskStores = append(m.diskStores, diskStore{device: device})
	return m.attachEndpoint(blockEndpoint{Store: index, Size: g.Size, BlockSize: g.LogicalBlockSize, ReadOnly: opts.ReadOnly || !device.Capabilities().Writable}, opts.Handle, opts.DevicePath, false)
}
func (f *Firmware) AttachBlockPartition(parent uint64, offset, size int64, path []byte, handle uint64) (uint64, error) {
	return f.machine.AttachBlockPartition(parent, offset, size, path, handle)
}
