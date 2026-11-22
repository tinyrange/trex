package power

import (
	"fmt"
	"math"
)

// Command/response queues hold 16-byte entries. Bit7 of the first byte
// transfers ownership to the consumer; the consumer clears it after reading.
// Queue storage is a DMA window, so its pages need not be contiguous in RAM.
type commandResponseQueue struct {
	table, address, size, producer uint64
	rpa                            *rpaEndpoint
}

// RegisterCRQ binds an opaque device unit to an existing DMA mapping. Queue
// bytes belong to the guest and are not cleared by registration.
func (m *Machine) RegisterCRQ(unit, table, address, size uint64) error {
	if m.crqs[unit] != nil {
		return fmt.Errorf("power: CRQ %x already registered", unit)
	}
	if address%4096 != 0 || size < 4096 || size%4096 != 0 || size > math.MaxInt {
		return fmt.Errorf("power: invalid CRQ geometry %x+%x", address, size)
	}
	if _, err := m.dmaTable(table, address, int(size), 0, false); err != nil {
		return err
	}
	if _, err := m.dmaTable(table, address, int(size), 0, true); err != nil {
		return err
	}
	if m.crqs == nil {
		m.crqs = make(map[uint64]*commandResponseQueue)
	}
	m.crqs[unit] = &commandResponseQueue{table: table, address: address, size: size}
	return nil
}

// UnregisterCRQ releases the binding without modifying guest queue bytes or
// translation entries. It reports an unknown unit rather than inventing one.
func (m *Machine) UnregisterCRQ(unit uint64) error {
	if m.crqs[unit] == nil {
		return fmt.Errorf("power: unknown CRQ %x", unit)
	}
	delete(m.crqs, unit)
	return nil
}

// PostCRQ publishes a complete entry. A full ring or inaccessible destination
// leaves both queue memory and the producer position unchanged. Notification
// routing remains the device backend's policy.
func (m *Machine) PostCRQ(unit uint64, entry []byte) error {
	q := m.crqs[unit]
	if q == nil {
		return fmt.Errorf("power: unknown CRQ %x", unit)
	}
	if len(entry) != 16 || entry[0]&0x80 == 0 {
		return fmt.Errorf("power: CRQ entry must be 16 bytes and owned by the consumer")
	}
	address := q.address + q.producer
	var old [16]byte
	if err := m.ReadDMA(q.table, address, old[:], 0); err != nil {
		return err
	}
	if old[0]&0x80 != 0 {
		return fmt.Errorf("power: CRQ %x full at %x", unit, q.producer)
	}
	// WriteDMA preflights the complete destination. Native execution cannot
	// observe this call partway through, so ownership is published with data.
	if err := m.WriteDMA(q.table, address, entry, 0); err != nil {
		return err
	}
	q.producer = (q.producer + 16) % q.size
	return nil
}

func cloneCRQs(queues map[uint64]*commandResponseQueue) map[uint64]*commandResponseQueue {
	out := make(map[uint64]*commandResponseQueue, len(queues))
	for unit, q := range queues {
		s := *q
		if q.rpa != nil {
			p := *q.rpa
			s.rpa = &p
		}
		out[unit] = &s
	}
	return out
}
