package acpi

import (
	"encoding/binary"
	"fmt"
)

// ARM64GenericTimer describes always-on, level-triggered active-high physical
// and virtual EL1 architectural timers. No memory-mapped timer frame is exposed.
func ARM64GenericTimer(physical, virtual uint32) ([]byte, error) {
	if physical < 16 || physical > 31 || virtual < 16 || virtual > 31 || physical == virtual {
		return nil, fmt.Errorf("architectural timers require distinct PPI interrupts")
	}
	body := make([]byte, 96-36)
	binary.LittleEndian.PutUint64(body, ^uint64(0))
	binary.LittleEndian.PutUint32(body[56-36:], physical)
	binary.LittleEndian.PutUint32(body[60-36:], 4)
	binary.LittleEndian.PutUint32(body[64-36:], virtual)
	binary.LittleEndian.PutUint32(body[68-36:], 4)
	binary.LittleEndian.PutUint64(body[80-36:], ^uint64(0))
	return Table("GTDT", body, 2, "TREXOS", "ARM64TMR", 1, "TREX", 1)
}

// ARM64Interrupts constructs an ACPI 6.0 MADT for a GICv3 distributor and an
// always-on redistributor range with one 128 KiB frame per supplied MPIDR.
// These are platform declarations; the caller must provide the named hardware.
func ARM64Interrupts(distributor, redistributor uint64, mpidrs []uint64, performanceInterrupt, maintenanceInterrupt uint32) ([]byte, error) {
	if len(mpidrs) == 0 || len(mpidrs) > 256 || distributor == 0 || distributor&0xfff != 0 || redistributor == 0 || redistributor&0xffff != 0 || redistributor > ^uint64(0)-uint64(len(mpidrs))*0x20000 {
		return nil, fmt.Errorf("invalid GICv3 topology")
	}
	body := make([]byte, 8) // No legacy local APIC or 8259 PIC.
	seen := map[uint64]bool{}
	for j, mpidr := range mpidrs {
		if mpidr & ^uint64(0xff00ffffff) != 0 || seen[mpidr] {
			return nil, fmt.Errorf("invalid or duplicate MPIDR %#x", mpidr)
		}
		seen[mpidr] = true
		gicc := make([]byte, 80)
		gicc[0], gicc[1] = 11, 80
		binary.LittleEndian.PutUint32(gicc[4:], uint32(j))
		binary.LittleEndian.PutUint32(gicc[8:], uint32(j))
		binary.LittleEndian.PutUint32(gicc[12:], 1) // Enabled
		binary.LittleEndian.PutUint32(gicc[20:], performanceInterrupt)
		binary.LittleEndian.PutUint32(gicc[56:], maintenanceInterrupt)
		// GICR Base is zero because the GICR structure describes the range.
		binary.LittleEndian.PutUint64(gicc[68:], mpidr)
		body = append(body, gicc...)
	}
	gicd := make([]byte, 24)
	gicd[0], gicd[1], gicd[20] = 12, 24, 3
	binary.LittleEndian.PutUint64(gicd[8:], distributor)
	body = append(body, gicd...)
	gicr := make([]byte, 16)
	gicr[0], gicr[1] = 14, 16
	binary.LittleEndian.PutUint64(gicr[4:], redistributor)
	binary.LittleEndian.PutUint32(gicr[12:], uint32(len(mpidrs))*0x20000)
	body = append(body, gicr...)
	return Table("APIC", body, 5, "TREXOS", "ARM64GIC", 1, "TREX", 1)
}
