package uefi

import (
	"github.com/tinyrange/trex/windows/guid"
	"sort"
)

type protocolOpen struct {
	Handle                        uint64
	GUID                          string
	Agent, Controller, Attributes uint64
}

func (m *Machine) openProtocol(a [8]uint64) uint64 {
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
