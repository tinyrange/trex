package uefi

import (
	"fmt"
	"github.com/tinyrange/trex/windows/guid"
	"slices"
)

type Variable struct {
	Name, GUID string
	Attributes uint32
	Data       []byte
}
type variableKey struct {
	Name string
	GUID [16]byte
}

// SetVariable configures the emulated firmware store. Persistence is owned by
// the caller; the in-memory store is included in execution checkpoints.
func (m *Machine) SetVariable(v Variable) error {
	raw, ok := guid.Parse(v.GUID)
	if !ok || v.Name == "" {
		return fmt.Errorf("uefi: invalid variable identity")
	}
	if len(v.Data) > 1<<20 {
		return fmt.Errorf("uefi: variable exceeds 1 MiB")
	}
	key := variableKey{v.Name, raw}
	if len(v.Data) == 0 {
		delete(m.variables, key)
		return nil
	}
	v.GUID = guid.Format(raw)
	v.Data = slices.Clone(v.Data)
	m.variables[key] = v
	return nil
}
func (m *Machine) getVariable(a [8]uint64) uint64 {
	name := m.text(a[0])
	var raw [16]byte
	copy(raw[:], m.get(a[1], 16))
	v, ok := m.variables[variableKey{name, raw}]
	if !ok {
		return notFound
	}
	size := m.read64(a[3])
	m.u64(a[3], uint64(len(v.Data)))
	if a[2] != 0 {
		m.u32(a[2], v.Attributes)
	}
	if size < uint64(len(v.Data)) {
		return bufferTooSmall
	}
	if a[4] == 0 {
		return invalidParameter
	}
	m.put(a[4], v.Data)
	return 0
}

func (m *Machine) setVariable(a [8]uint64) uint64 {
	if a[0] == 0 || a[1] == 0 || a[2] > 0xffffffff {
		return invalidParameter
	}
	if a[3] > 1<<20 {
		return outOfResources
	}
	name := m.text(a[0])
	if name == "" {
		return invalidParameter
	}
	var raw [16]byte
	copy(raw[:], m.get(a[1], 16))
	attrs := uint32(a[2])
	key := variableKey{name, raw}
	if attrs & ^uint32(0x47) != 0 {
		return unsupported
	}
	if attrs&4 != 0 && attrs&2 == 0 {
		return invalidParameter
	}
	old, exists := m.variables[key]
	if a[3] == 0 && attrs&0x40 == 0 {
		if !exists {
			return notFound
		}
		delete(m.variables, key)
		return 0
	}
	if attrs&2 == 0 {
		return invalidParameter
	}
	data := m.get(a[4], a[3])
	if exists {
		if old.Attributes != attrs&^0x40 {
			return invalidParameter
		}
		if attrs&0x40 != 0 {
			data = append(slices.Clone(old.Data), data...)
		}
	}
	if err := m.SetVariable(Variable{Name: name, GUID: guid.Format(raw), Attributes: attrs &^ 0x40, Data: data}); err != nil {
		return outOfResources
	}
	return 0
}
