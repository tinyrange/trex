package uefi

import (
	"fmt"
	"github.com/tinyrange/trex/emulator/cpu"
)

func (m *Machine) bulkMemory(address, size uint64, access cpu.Access) (cpu.Memory, error) {
	if m.memory == nil {
		return nil, fmt.Errorf("uefi: machine is closed")
	}
	if size > m.opts.Memory || size > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("uefi: bulk transfer exceeds RAM size")
	}
	memory := m.processor.VirtualMemory(m.executionMemory())
	if size != 0 {
		if err := memory.CheckMemory(address, int(size), access); err != nil {
			return nil, err
		}
	}
	return memory, nil
}

// CopyVirtualMemory implements memmove with bounded scratch space. Validate
// both complete ranges before writing; preflight faults preserve the destination.
func (m *Machine) CopyVirtualMemory(destination, source, size uint64) error {
	memory, err := m.bulkMemory(destination, size, cpu.Write)
	if err != nil {
		return err
	}
	if size == 0 {
		return nil
	}
	if err = memory.CheckMemory(source, int(size), cpu.Read); err != nil {
		return err
	}
	backwards := source < destination && destination-source < size
	for done := uint64(0); done < size; {
		n := min(uint64(len(m.bulkBuffer)), size-done)
		offset := done
		if backwards {
			offset = size - done - n
		}
		buffer := m.bulkBuffer[:n]
		if err = memory.ReadMemory(source+offset, buffer, cpu.Read); err != nil {
			return err
		}
		if err = memory.WriteMemory(destination+offset, buffer); err != nil {
			return err
		}
		done += n
	}
	return nil
}

// FillVirtualMemory validates the full range before writing a repeated byte.
func (m *Machine) FillVirtualMemory(destination, size uint64, value byte) error {
	memory, err := m.bulkMemory(destination, size, cpu.Write)
	if err != nil {
		return err
	}
	buffer := m.bulkBuffer[:min(size, uint64(len(m.bulkBuffer)))]
	if value == 0 {
		clear(buffer)
	} else {
		for j := range buffer {
			buffer[j] = value
		}
	}
	for done := uint64(0); done < size; {
		n := min(uint64(len(buffer)), size-done)
		if err = memory.WriteMemory(destination+done, buffer[:n]); err != nil {
			return err
		}
		done += n
	}
	return nil
}
