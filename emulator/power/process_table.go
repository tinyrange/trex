package power

import "fmt"

const (
	sprLPCR  = 318
	lpcrUPRT = uint64(1) << 22
	lpcrHR   = uint64(1) << 20
	lpcrGTSE = uint64(1) << 10
)

type hashProcessTable struct {
	Entry      uint64
	Registered bool
}

// RegisterHashProcessTable registers the ISA v3 hash/SLB PATE1 fields. With
// UPRT clear, procTable is the 38-bit encoded field, not a guest table pointer;
// hardware continues to use SLBs and the existing partition HPT. This is the
// H_REGISTER_PROC_TBL modify/register profile (flags18), without GTSE, radix
// or memory-resident segment tables. Other profiles are not implied.
func (m *Machine) RegisterHashProcessTable(procTable, pageSize, tableSize uint64) error {
	if procTable>>38 != 0 || pageSize&^7 != 0 || tableSize > 24 {
		return fmt.Errorf("power: invalid hash/SLB process registration")
	}
	m.hashProcessTable = hashProcessTable{Entry: procTable<<25 | pageSize<<5 | tableSize, Registered: true}
	for _, c := range m.CPUs {
		c.SPR[sprLPCR] &^= lpcrUPRT | lpcrHR | lpcrGTSE
		c.tlbGen++
	}
	return nil
}

// HashProcessTable reports the registered PATE1 word and whether registration
// has occurred. A zero word can itself be a valid registration.
func (m *Machine) HashProcessTable() (uint64, bool) {
	return m.hashProcessTable.Entry, m.hashProcessTable.Registered
}
