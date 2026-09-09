package uefi

import (
	"fmt"
	"github.com/tinyrange/trex/windows/guid"
	"sort"
)

// InstallConfigurationTable installs bytes such as an ACPI RSDP or SMBIOS entry
// point in a caller-selected EFI memory type. Addresses inside remain explicit
// guest addresses; no host firmware or paths are consulted.
func (m *Machine) InstallConfigurationTable(identifier string, data []byte, memoryType uint32) (uint64, error) {
	raw, ok := guid.Parse(identifier)
	if !ok || len(data) == 0 || memoryType > 14 {
		return 0, fmt.Errorf("uefi: invalid configuration table")
	}
	p := m.allocate(0, uint64(memoryType), (uint64(len(data))+4095)/page, 0)
	if p == 0 {
		return 0, fmt.Errorf("uefi: no table memory")
	}
	m.put(p, data)
	if status := m.configurationTable(raw, p); status != 0 {
		return 0, fmt.Errorf("uefi: configuration table status %#x", status)
	}
	return p, m.err
}
func (m *Machine) configurationTable(raw [16]byte, p uint64) uint64 {
	if p == 0 {
		if _, ok := m.configuration[raw]; !ok {
			return notFound
		}
		delete(m.configuration, raw)
	} else {
		if _, ok := m.configuration[raw]; !ok && len(m.configuration) == 128 {
			return outOfResources
		}
		m.configuration[raw] = p
	}
	keys := make([][16]byte, 0, len(m.configuration))
	for k := range m.configuration {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return guid.Format(keys[i]) < guid.Format(keys[j]) })
	base := m.ramBase + 0x3000
	for j, k := range keys {
		m.put(base+uint64(j)*24, k[:])
		m.u64(base+uint64(j)*24+16, m.configuration[k])
	}
	m.u64(m.systemTable+104, uint64(len(keys)))
	m.u64(m.systemTable+112, base)
	m.checksum(m.systemTable, 120)
	return 0
}
