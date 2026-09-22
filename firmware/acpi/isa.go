package acpi

import (
	"encoding/binary"
	"fmt"
)

// ISADevice describes a fixed, non-configurable device under the system bus.
// Ports are base/length pairs; IRQs use the ISA edge/high convention.
type ISADevice struct {
	Name, ID string
	// Parent is an absolute ACPI scope; the default is the system bus.
	Parent string
	UID    uint32
	Ports  [][2]uint16
	IRQs   []uint8
	// Memory contains fixed base/length pairs in the 32-bit physical address space.
	Memory [][2]uint32
}

func (d ISADevice) AML() ([]byte, error) {
	if len(d.Name) != 4 {
		return nil, fmt.Errorf("ISA device name must contain four characters")
	}
	if err := acpiNameString("ISA device name", d.Name, 4, 4); err != nil {
		return nil, err
	}
	id, ok := acpiEISAID(d.ID)
	if !ok {
		return nil, fmt.Errorf("invalid ISA device ID %q", d.ID)
	}
	body := []byte(d.Name)
	body = append(body, amlName("_HID", amlInteger(uint64(id)))...)
	body = append(body, amlName("_UID", amlInteger(uint64(d.UID)))...)
	var resources []byte
	for _, port := range d.Ports {
		if port[1] == 0 || port[1] > 255 || uint32(port[0])+uint32(port[1]) > 65536 {
			return nil, fmt.Errorf("invalid ISA port range")
		}
		// IO descriptor: 16-bit decode, fixed minimum/maximum, alignment one.
		resources = append(resources, 0x47, 1)
		resources = binary.LittleEndian.AppendUint16(resources, port[0])
		resources = binary.LittleEndian.AppendUint16(resources, port[0])
		resources = append(resources, 1, byte(port[1]))
	}
	for _, region := range d.Memory {
		if region[1] == 0 || uint64(region[0])+uint64(region[1]) > 1<<32 {
			return nil, fmt.Errorf("invalid fixed memory range")
		}
		resources = append(resources, 0x86, 9, 0, 1)
		resources = binary.LittleEndian.AppendUint32(resources, region[0])
		resources = binary.LittleEndian.AppendUint32(resources, region[1])
	}
	for _, irq := range d.IRQs {
		if irq > 15 {
			return nil, fmt.Errorf("invalid ISA IRQ %d", irq)
		}
		resources = binary.LittleEndian.AppendUint16(append(resources, 0x22), 1<<irq)
	}
	resources = append(resources, 0x79, 0)
	buffer := append(amlInteger(uint64(len(resources))), resources...)
	body = append(body, amlName("_CRS", amlPackage([]byte{0x11}, buffer))...)
	parent := d.Parent
	if parent == "" {
		parent = `\_SB`
	}
	scope, err := acpiAbsoluteName(parent)
	if err != nil {
		return nil, err
	}
	scope = append(scope, amlPackage([]byte{0x5b, 0x82}, body)...)
	return amlPackage([]byte{0x10}, scope), nil
}

// LegacyProcessorAML describes a CPU without firmware throttling registers.
func LegacyProcessorAML(name string, id byte) ([]byte, error) {
	if len(name) != 4 {
		return nil, fmt.Errorf("processor name must contain four characters")
	}
	if err := acpiNameString("processor name", name, 4, 4); err != nil {
		return nil, err
	}
	body := append([]byte(name), id, 0, 0, 0, 0, 0)
	scope := append([]byte{'\\', '_', 'P', 'R', '_'}, amlPackage([]byte{0x5b, 0x83}, body)...)
	return amlPackage([]byte{0x10}, scope), nil
}
