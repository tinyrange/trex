package acpi

import (
	"encoding/binary"
	"fmt"
)

type PCIInterrupt struct {
	Device, Pin uint8
	Interrupt   uint32
}
type PCIRoot struct {
	Segment                uint16
	FirstBus, LastBus      uint8
	MemoryBase, MemorySize uint64
	Interrupts             []PCIInterrupt
}

func PCIConfiguration(base uint64, segment uint16, first, last uint8) ([]byte, error) {
	if base&0xfffff != 0 || first > last || base+(uint64(last)+1)*0x100000 < base {
		return nil, fmt.Errorf("invalid ECAM range")
	}
	body := make([]byte, 24)
	binary.LittleEndian.PutUint64(body[8:], base)
	binary.LittleEndian.PutUint16(body[16:], segment)
	body[18], body[19] = first, last
	return Table("MCFG", body, 1, "TREXOS", "PCI ECAM", 1, "TREX", 1)
}

func amlPackage(op []byte, body []byte) []byte {
	out := append([]byte(nil), op...)
	out = append(out, acpiPackageLength(len(body))...)
	return append(out, body...)
}
func amlInteger(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	if v == 1 {
		return []byte{1}
	}
	if v <= 0xffffffff {
		return binary.LittleEndian.AppendUint32([]byte{0x0c}, uint32(v))
	}
	return binary.LittleEndian.AppendUint64([]byte{0x0e}, v)
}
func amlName(name string, value []byte) []byte { return append(append([]byte{8}, name...), value...) }

// AML describes an ECAM PCI root with a fixed memory window and INTx routing.
// Interrupt pins use the ACPI numbering (0=INTA through 3=INTD).
func (p PCIRoot) AML() ([]byte, error) {
	if p.FirstBus > p.LastBus || p.MemorySize == 0 || p.MemoryBase+p.MemorySize < p.MemoryBase || len(p.Interrupts) > 255 {
		return nil, fmt.Errorf("invalid PCI root resources")
	}
	body := []byte("PCI0")
	for _, id := range []struct{ name, value string }{{"_HID", "PNP0A08"}, {"_CID", "PNP0A03"}} {
		v, _ := acpiEISAID(id.value)
		body = append(body, amlName(id.name, amlInteger(uint64(v)))...)
	}
	for _, v := range []struct {
		name  string
		value uint64
	}{{"_SEG", uint64(p.Segment)}, {"_BBN", uint64(p.FirstBus)}, {"_UID", 0}, {"_CCA", 1}} {
		body = append(body, amlName(v.name, amlInteger(v.value))...)
	}
	bus := []byte{0x88, 13, 0, 2, 0x0c, 0}
	for _, v := range []uint16{0, uint16(p.FirstBus), uint16(p.LastBus), 0, uint16(p.LastBus) - uint16(p.FirstBus) + 1} {
		bus = binary.LittleEndian.AppendUint16(bus, v)
	}
	resources := append(bus, 0x8a, 43, 0, 0, 0x0c, 1)
	for _, v := range []uint64{0, p.MemoryBase, p.MemoryBase + p.MemorySize - 1, 0, p.MemorySize} {
		resources = binary.LittleEndian.AppendUint64(resources, v)
	}
	resources = append(resources, 0x79, 0)
	buffer := append(amlInteger(uint64(len(resources))), resources...)
	body = append(body, amlName("_CRS", amlPackage([]byte{0x11}, buffer))...)
	routes := []byte{byte(len(p.Interrupts))}
	for _, r := range p.Interrupts {
		if r.Device > 31 || r.Pin > 3 || r.Interrupt < 32 {
			return nil, fmt.Errorf("invalid PCI interrupt route")
		}
		row := []byte{4}
		for _, v := range []uint64{uint64(r.Device)<<16 | 0xffff, uint64(r.Pin), 0, uint64(r.Interrupt)} {
			row = append(row, amlInteger(v)...)
		}
		routes = append(routes, amlPackage([]byte{0x12}, row)...)
	}
	body = append(body, amlName("_PRT", amlPackage([]byte{0x12}, routes))...)
	scope := append([]byte{'\\', '_', 'S', 'B', '_'}, amlPackage([]byte{0x5b, 0x82}, body)...)
	return amlPackage([]byte{0x10}, scope), nil
}
