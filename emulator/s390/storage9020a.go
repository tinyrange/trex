package s390

const seLogoutSize9020A = 7 * 4

type storageElement9020A struct {
	Cycle       storageCycle9020
	IgnoreError bool
	Logout      storageLogout9020
}

func (m *Machine) recordStorage9020A(address, size uint32, acc access, response, key byte, ignoreError bool) {
	word := (address + size - 1) &^ 3
	start := max(address, word)
	state := &m.storage9020A[word/bytesPer9020ASE]
	state.Cycle = storageCycle9020{
		Data: uint64(be.Uint32(m.S.Mem[word:])), Address: start % bytesPer9020ASE,
		Response: response, Operation: seFetch9020,
		InputKey: key << 1, StoredKey: *m.S.key(word) >> 3,
		BadDataParity: m.storageBadParity9020[word&^7] >> (4 - (word & 4)) & 0xf,
	}
	if acc == accStore {
		lo, hi := start-word, address+size-word
		state.Cycle.Marks = byte(0xf >> lo & (0xf << (4 - hi)))
		state.Cycle.Operation = seStore9020
	}
	state.IgnoreError = ignoreError
}

// The 7251-03 sends five responses over 36 lines (CBB9A0 fig. 3-25).
// The first two responses include four parity positions each. The CE
// saves their four low bits in positions 24–27 of the following word
// (FAA formatter D0D10700 statements 1211–1216 and 2659–2672).
func (m *Machine) liveStorageLogout9020A(id int) [seLogoutSize9020]byte {
	state := &m.storage9020A[id-1]
	cycle := state.Cycle
	ccr := m.ccr9020(7 + uint32(id))
	connections := byte((ccr&ceMask9020)>>5 | ccr&ioceMask9020)
	controls := byte(ccr >> 24 & 0xfc)
	request := uint32(cycle.Response>>1&0x78 | cycle.Response&7)
	configuration := oddParity9020(connections)<<31 | uint32(connections)<<24 |
		request<<16 | request<<9 | oddParity9020(controls)<<8 | uint32(controls)

	var dataBus, addressBus uint64
	var protection, checks uint32
	if cycle.Operation != 0 {
		for i := range 4 {
			b := byte(cycle.Data >> (24 - 8*i))
			p := oddParity9020(b) ^ uint32(cycle.BadDataParity>>(3-i)&1)
			dataBus = dataBus<<9 | uint64(p)<<8 | uint64(b)
		}
		addressBus = uint64(oddParity9020(cycle.Marks))<<8 | uint64(cycle.Marks)<<4
		for i := range 3 {
			b := byte(cycle.Address >> (16 - 8*i))
			addressBus = addressBus<<9 | uint64(oddParity9020(b))<<8 | uint64(b)
		}
		protection = oddParity9020(cycle.StoredKey)<<31 | uint32(cycle.StoredKey)<<26 |
			oddParity9020(cycle.InputKey)<<22 | uint32(cycle.InputKey)<<17
		protection |= 1 << 11 // Accept.
		if cycle.Operation == seStore9020 {
			protection |= 1 << 12 // Data Gate.
		}
		if state.IgnoreError {
			protection |= 1 << 7
		}
		if cycle.BadDataParity != 0 {
			checks |= 1 << 16 // SDR check.
		}
	}
	var frame [seLogoutSize9020]byte
	words := [...]uint32{
		uint32(dataBus >> 4), uint32(dataBus&0xf) << 4,
		uint32(addressBus >> 4), uint32(addressBus&0xf) << 4,
		configuration, protection, checks,
	}
	for i, word := range words {
		be.PutUint32(frame[4*i:], word)
	}
	return frame
}

// The kernel number is part of the instruction, not a storage address.
// D0C00C00 passes the physical element in GR1 bits 8–15 and consumes
// the seven words placed immediately after DIAGNOSE.
func (c *CPU) logoutStorage9020A() {
	id := int(c.GR[1] >> 16 & 0xff)
	result := c.next
	c.checkAlignment360(result, 4)
	c.logoutStorage9020To(result, 0, id, seLogoutSize9020A, 4)
	c.next = (result + seLogoutSize9020A) & c.amask
}
