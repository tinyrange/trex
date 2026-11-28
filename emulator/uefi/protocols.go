package uefi

import (
	"bytes"
	"sort"

	"github.com/tinyrange/trex/windows/guid"
)

type protocolOpen struct {
	Handle                        uint64
	GUID                          string
	Agent, Controller, Attributes uint64
}

func (m *Machine) openProtocol(a [8]uint64) uint64 {
	// Attributes is UINT32. On the x64 ABI its stack slot may have arbitrary
	// upper bytes; these are not part of the argument.
	a[5] = uint64(uint32(a[5]))
	if m.protocols[a[0]] == nil {
		return invalidParameter
	}
	var raw [16]byte
	copy(raw[:], m.get(a[1], 16))
	identifier := guid.Format(raw)
	p := m.protocols[a[0]][identifier]
	if p == 0 {
		return unsupported
	}
	switch a[5] {
	case 1, 2, 4, 8, 16, 32, 48:
	default:
		return invalidParameter
	}
	if a[5] == 4 {
		return 0
	}
	if a[2] == 0 {
		return invalidParameter
	}
	key := protocolOpen{a[0], identifier, a[3], a[4], a[5]}
	for open, count := range m.protocolOpens {
		if count != 0 && open.Handle == a[0] && open.GUID == identifier && open.Agent != a[3] && (open.Attributes&32 != 0 || a[5]&32 != 0) {
			return efiError | 15
		}
	}
	m.u64(a[2], p)
	m.protocolOpens[key]++
	return 0
}
func (m *Machine) closeProtocol(a [8]uint64) uint64 {
	var raw [16]byte
	copy(raw[:], m.get(a[1], 16))
	identifier := guid.Format(raw)
	for key, count := range m.protocolOpens {
		if key.Handle == a[0] && key.GUID == identifier && key.Agent == a[2] && key.Controller == a[3] {
			if count == 1 {
				delete(m.protocolOpens, key)
			} else {
				m.protocolOpens[key] = count - 1
			}
			return 0
		}
	}
	return notFound
}

func (m *Machine) handles(identifier string) []uint64 {
	var handles []uint64
	for handle, protocols := range m.protocols {
		if identifier == "" || protocols[identifier] != 0 {
			handles = append(handles, handle)
		}
	}
	sort.Slice(handles, func(i, j int) bool { return handles[i] < handles[j] })
	return handles
}
func (m *Machine) locateHandles(a [8]uint64, allocate bool) (uint64, bool) {
	identifier := ""
	switch a[0] {
	case 0:
	case 2:
		var raw [16]byte
		copy(raw[:], m.get(a[1], 16))
		identifier = guid.Format(raw)
	case 1:
		return 0, false
	default:
		return invalidParameter, true
	}
	handles := m.handles(identifier)
	if len(handles) == 0 {
		return notFound, true
	}
	size := uint64(len(handles)) * 8
	buffer := a[4]
	if allocate {
		buffer = m.allocate(0, 4, (size+4095)/page, 0)
		if buffer == 0 {
			return outOfResources, true
		}
		m.u64(a[3], uint64(len(handles)))
		m.u64(a[4], buffer)
	} else {
		capacity := m.read64(a[3])
		m.u64(a[3], size)
		if capacity < size {
			return bufferTooSmall, true
		}
		if buffer == 0 {
			return invalidParameter, true
		}
	}
	for j, handle := range handles {
		m.u64(buffer+uint64(j)*8, handle)
	}
	return 0, true
}

func (m *Machine) locateDevicePath(protocol, pathPointer, handlePointer uint64) uint64 {
	if protocol == 0 || pathPointer == 0 || handlePointer == 0 {
		return invalidParameter
	}
	address := m.read64(pathPointer)
	path, valid := m.copyDevicePath(address)
	if !valid || len(path) < 4 {
		return invalidParameter
	}
	identifier := guid.Format([16]byte(m.get(protocol, 16)))
	var best uint64
	bestLength := -1
	for _, handle := range m.handles(identifier) {
		candidateAddress := m.protocols[handle][devicePathGUID]
		if candidateAddress == 0 {
			continue
		}
		candidate, valid := m.copyDevicePath(candidateAddress)
		if !valid || len(candidate) < 4 {
			continue
		}
		prefix := candidate[:len(candidate)-4]
		if len(prefix) > bestLength && bytes.HasPrefix(path, prefix) {
			best, bestLength = handle, len(prefix)
		}
	}
	if best == 0 {
		return notFound
	}
	m.u64(pathPointer, address+uint64(bestLength))
	m.u64(handlePointer, best)
	return 0
}

// updateProtocols implements the bounded varargs form used by EFI
// applications. Registration is atomic if any pair is invalid.
func (f *Firmware) updateProtocols(a [10]uint64, install bool) uint64 {
	m := f.machine
	if a[0] == 0 || m.exited {
		return invalidParameter
	}
	handle := a[0]
	if install {
		handle = m.read64(a[0])
	}
	existing := m.protocols[handle]
	if handle != 0 && existing == nil {
		return invalidParameter
	}
	pairs := make(map[string]uint64)
	terminated := false
	for i := 1; i < len(a); i += 2 {
		if a[i] == 0 {
			terminated = true
			break
		}
		if i+1 >= len(a) || a[i+1] == 0 {
			return invalidParameter
		}
		key := guid.Format([16]byte(m.get(a[i], 16)))
		if pairs[key] != 0 || (install && existing[key] != 0) || (!install && existing[key] != a[i+1]) {
			return invalidParameter
		}
		pairs[key] = a[i+1]
	}
	if !terminated || len(pairs) == 0 {
		return invalidParameter
	}
	if install {
		if handle == 0 {
			handle = m.allocate(0, 4, 1, 0)
			if handle == 0 {
				return outOfResources
			}
			existing = make(map[string]uint64)
			m.protocols[handle] = existing
			f.protocolHandles[handle] = true
			m.u64(a[0], handle)
		}
		for key, iface := range pairs {
			existing[key] = iface
		}
		return 0
	}
	for key := range pairs {
		delete(existing, key)
	}
	if len(existing) == 0 && f.protocolHandles[handle] {
		delete(m.protocols, handle)
		delete(f.protocolHandles, handle)
		m.free(handle, 1)
	}
	return 0
}
