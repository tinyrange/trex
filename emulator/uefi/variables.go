package uefi

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/windows/guid"
	"slices"
	"sort"
	"unicode/utf16"
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
	if !ok || m.exited && v.Attributes&4 == 0 {
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

// getNextVariableName enumerates a stable ordering of visible variables. A
// short output buffer leaves the input name and GUID intact for a retry.
func (m *Machine) getNextVariableName(a [8]uint64) uint64 {
	if a[0] == 0 || a[1] == 0 || a[2] == 0 {
		return invalidParameter
	}
	size := m.read64(a[0])
	if size < 2 || size > 65536 {
		return invalidParameter
	}
	rawName := m.get(a[1], size)
	if m.err != nil {
		return invalidParameter
	}
	var units []uint16
	terminated := false
	for i := 0; i+1 < len(rawName); i += 2 {
		v := binary.LittleEndian.Uint16(rawName[i:])
		if v == 0 {
			terminated = true
			break
		}
		units = append(units, v)
	}
	if !terminated {
		return invalidParameter
	}
	name := string(utf16.Decode(units))
	var identifier [16]byte
	if name != "" {
		copy(identifier[:], m.get(a[2], 16))
	}
	keys := make([]variableKey, 0, len(m.variables))
	for key, v := range m.variables {
		if !m.exited || v.Attributes&4 != 0 {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].GUID != keys[j].GUID {
			return guid.Format(keys[i].GUID) < guid.Format(keys[j].GUID)
		}
		return keys[i].Name < keys[j].Name
	})
	next := 0
	if name != "" {
		next = -1
		for i, key := range keys {
			if key.Name == name && key.GUID == identifier {
				next = i + 1
				break
			}
		}
		if next < 0 {
			return invalidParameter
		}
	}
	if next >= len(keys) {
		return notFound
	}
	key := keys[next]
	encoded := utf16.Encode([]rune(key.Name))
	required := uint64((len(encoded) + 1) * 2)
	m.u64(a[0], required)
	if size < required {
		return bufferTooSmall
	}
	out := make([]byte, required)
	for i, v := range encoded {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	m.put(a[1], out)
	m.put(a[2], key.GUID[:])
	return 0
}
