package uefi

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/tinyrange/trex/emulator/arm64"
	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/windows/guid"
)

// Checkpoint captures guest CPU, RAM, allocations and firmware metadata. Observer
// callbacks belong to the caller; their mutable state must be captured separately.
type Checkpoint struct {
	owner *Machine
	state *Machine
}

func (m *Machine) clone() (*Machine, error) {
	v := *m
	v.rewrites = maps.Clone(m.rewrites)
	v.observation = nil
	v.processor = m.processor.Clone().(*arm64.CPU)
	v.memory = m.memory.Clone()
	v.allocations = slices.Clone(m.allocations)
	v.services = maps.Clone(m.services)
	v.protocols = make(map[uint64]map[string]uint64, len(m.protocols))
	v.variables = maps.Clone(m.variables)
	v.configuration = maps.Clone(m.configuration)
	v.protocolOpens = maps.Clone(m.protocolOpens)
	v.blockHandles = maps.Clone(m.blockHandles)
	v.blockInterfaces = maps.Clone(m.blockInterfaces)
	v.diskStores = make([]diskStore, len(m.diskStores))
	for j, s := range m.diskStores {
		copy, err := s.clone()
		if err != nil {
			return nil, err
		}
		v.diskStores[j] = copy
	}
	for k, variable := range v.variables {
		variable.Data = slices.Clone(variable.Data)
		v.variables[k] = variable
	}
	for h, p := range m.protocols {
		v.protocols[h] = maps.Clone(p)
	}
	v.opts.Registers = maps.Clone(m.opts.Registers)
	v.opts.DevicePath = slices.Clone(m.opts.DevicePath)
	v.opts.EventKinds = slices.Clone(m.opts.EventKinds)
	return &v, nil
}
func (m *Machine) Checkpoint() (*Checkpoint, error) {
	if m.memory == nil {
		return nil, fmt.Errorf("uefi: machine is closed")
	}
	copy, err := m.clone()
	if err != nil {
		return nil, err
	}
	return &Checkpoint{m, copy}, nil
}
func (m *Machine) Restore(c *Checkpoint) error {
	if c == nil || c.owner != m {
		return fmt.Errorf("uefi: checkpoint belongs to another machine")
	}
	observe := m.opts.Observe
	copy, err := c.state.clone()
	if err != nil {
		return err
	}
	*m = *copy
	m.opts.Observe = observe
	return nil
}
func (m *Machine) Register(name string) (uint64, error)    { return m.processor.Register(name) }
func (m *Machine) SetRegister(name string, v uint64) error { return m.processor.SetRegister(name, v) }
func (m *Machine) ReadMemory(address uint64, destination []byte) error {
	if m.memory == nil {
		return fmt.Errorf("uefi: machine is closed")
	}
	return m.memory.ReadMemory(address, destination, cpu.Read)
}
func (m *Machine) ReadVirtualMemory(address uint64, destination []byte) error {
	if m.memory == nil {
		return fmt.Errorf("uefi: machine is closed")
	}
	return m.processor.VirtualMemory(m.memory).ReadMemory(address, destination, cpu.Read)
}
func (m *Machine) WriteVirtualMemory(address uint64, source []byte) error {
	if m.memory == nil {
		return fmt.Errorf("uefi: machine is closed")
	}
	return m.processor.VirtualMemory(m.memory).WriteMemory(address, source)
}
func (m *Machine) Translate(address uint64, access cpu.Access) (uint64, error) {
	if m.memory == nil {
		return 0, fmt.Errorf("uefi: machine is closed")
	}
	return m.processor.Translate(m.memory, address, access)
}
func (m *Machine) WriteMemory(address uint64, source []byte) error {
	if m.memory == nil {
		return fmt.Errorf("uefi: machine is closed")
	}
	if err := m.memory.WriteMemory(address, source); err != nil {
		return err
	}
	m.processor.InvalidateExclusive(address, len(source))
	return nil
}
func (m *Machine) Addresses() map[string]uint64 {
	if m.memory == nil {
		return nil
	}
	return map[string]uint64{"ram": m.ramBase, "system_table": m.systemTable, "boot_services": m.bootTable, "image_handle": m.imageHandle, "device_handle": m.ramBase + 0xb00, "image_base": m.read64(m.ramBase + 0xa00 + 64), "image_size": m.read64(m.ramBase + 0xa00 + 72)}
}

// InstallProtocol maps caller-supplied protocol bytes in guest RAM. Unknown
// service entrypoints remain explicit execution stops.
func (m *Machine) InstallProtocol(handle uint64, identifier string, data []byte) (uint64, error) {
	if m.memory == nil {
		return 0, fmt.Errorf("uefi: machine is closed")
	}
	raw, ok := guid.Parse(identifier)
	if !ok {
		return 0, fmt.Errorf("uefi: invalid protocol GUID")
	}
	if len(data) == 0 {
		return 0, fmt.Errorf("uefi: empty protocol")
	}
	if handle == 0 {
		handle = m.allocate(0, 4, 1, 0)
		if handle == 0 {
			return 0, fmt.Errorf("uefi: no handle memory")
		}
	}
	name := guid.Format(raw)
	if _, exists := m.protocols[handle][name]; exists {
		return 0, fmt.Errorf("uefi: protocol already installed")
	}
	p := m.allocate(0, 4, (uint64(len(data))+4095)/page, 0)
	if p == 0 {
		return 0, fmt.Errorf("uefi: no protocol memory")
	}
	if err := m.memory.WriteMemory(p, data); err != nil {
		return 0, err
	}
	if m.protocols[handle] == nil {
		m.protocols[handle] = map[string]uint64{}
	}
	m.protocols[handle][name] = p
	return handle, nil
}

type RunOptions struct {
	DisableAcceleration     bool
	DisableTranslationCache bool
	DisableDecodeCache      bool
	Clock                   interface{ Now() time.Duration }
	Timeout                 time.Duration
	Watches                 []Watch
	Steps                   uint64
	StopPCs                 []uint64
	// StopServices stops before dispatch, permitting argument inspection.
	StopServices []string
	// Trace addresses are collected in a fixed-size last-N ring.
	TraceLimit int
	// SampleInterval emits a sample event before every Nth execution unit.
	// Zero disables sampling. Unlike tracing it retains native acceleration.
	SampleInterval uint64
}

// Close releases live RAM and overlays. Inputs remain owned by the caller;
// retained checkpoints own their independent copies until they are discarded.
func (m *Machine) Close() {
	m.processor.ClearTranslationCache()
	m.memory = nil
	m.diskStores = nil
}
