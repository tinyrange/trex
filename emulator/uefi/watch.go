package uefi

import (
	"github.com/tinyrange/trex/emulator/cpu"
	"slices"
)

// Watch observes completed memory accesses. A matching instruction/service
// finishes before Run returns, so resuming never repeats a partial write.
type Watch struct {
	Address, Size uint64
	Access        cpu.Access
}
type observation struct {
	watches []Watch
	hit     bool
}
type watchedMemory struct{ machine *Machine }

func (m *Machine) executionMemory() cpu.Memory {
	if m.runtimeMemory != nil {
		return m.runtimeMemory
	}
	if m.observation == nil || len(m.observation.watches) == 0 {
		return m.memory
	}
	return watchedMemory{m}
}
func (w watchedMemory) CheckMemory(a uint64, n int, access cpu.Access) error {
	return w.machine.memory.CheckMemory(a, n, access)
}
func (w watchedMemory) ReadMemory(a uint64, b []byte, access cpu.Access) error {
	if err := w.machine.memory.ReadMemory(a, b, access); err != nil {
		return err
	}
	w.observe(a, b, access)
	return nil
}
func (w watchedMemory) WriteMemory(a uint64, b []byte) error {
	if err := w.machine.memory.WriteMemory(a, b); err != nil {
		return err
	}
	w.observe(a, b, cpu.Write)
	return nil
}
func (w watchedMemory) observe(a uint64, b []byte, access cpu.Access) {
	m := w.machine
	for _, watch := range m.observation.watches {
		if watch.Access&access != 0 && len(b) != 0 && a < watch.Address+watch.Size && watch.Address < a+uint64(len(b)) {
			m.observation.hit = true
			m.emit(Event{Kind: "memory", PC: m.processor.PC(), Address: a, Size: uint64(len(b)), Access: access, Data: slices.Clone(b[:min(len(b), 64)])})
			return
		}
	}
}
