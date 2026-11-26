package s390

import (
	"fmt"
	"math/bits"
)

// A 9020 SE keeps separate latches for its even and odd doublewords.
type storageCycle9020 struct {
	Data                uint64
	Address             uint32
	Marks, Response     byte
	InputKey, StoredKey byte
	Operation           uint16
	BadDataParity       byte
	BadMarkParity       bool
	BadInputKeyParity   bool
	BadStoredKeyParity  bool
	BadAddressParity    storageCycleFlags9020
}

type storageCycleFlags9020 byte

const (
	badAddressPB9020 storageCycleFlags9020 = 1 << iota
	badAddressPA9020
	badMarkParity9020
	ignoreStorageCheck9020
	badSumParity9020
	badStoredKeyParity9020
	badAddressParity9020 = badAddressPA9020 | badAddressPB9020
)

const (
	seStore9020           = 1 << 12 // Figure 12-5, word 4/10, bit 19.
	seFetch9020           = 1 << 11 // Bit 20.
	seInsertKey9020       = 1 << 15 // Figure 12-5, word 4, bit 16.
	seSetKey9020          = 1 << 14 // Bit 17.
	seCommonOp9020        = seInsertKey9020 | seSetKey9020
	seDataParityCheck9020 = 1 << 29 // Figure 12-5, word 5/11, bit 2.
	seMarkParityCheck9020 = 1 << 31 // Word 5/11, bit 0.
	seAddrParityCheck9020 = 1 << 30 // Word 5/11, bit 1.
	seSPParityCheck9020   = 1 << 28 // Word 5/11, bit 3.
)

// SetStorageDataParity9020 inverts or restores the parity bit of a physical
// storage byte without modifying its data. Call between Run calls.
func (m *Machine) SetStorageDataParity9020(address uint32, bad bool) error {
	width := m.storageWordSize9020()
	if !m.Model9020 || m.cfg.IOCE || address/m.storageElementSize9020() >= uint32(m.storageSlots9020()) || !m.S.valid(address&^(width-1), width) {
		return fmt.Errorf("9020 storage data parity: invalid physical address %08X", address)
	}
	if !bad {
		m.clearStorageDataParity9020(address, 1)
		return nil
	}
	m.markStorageDataParity9020(address, 1)
	return nil
}

// Only the lanes selected by the store's marks receive the reversed parity.
func (m *Machine) markStorageDataParity9020(address, size uint32) {
	if m.storageBadParity9020 == nil {
		m.storageBadParity9020 = make(map[uint32]byte)
	}
	for word, end := address&^7, address+size; word < end; word += 8 {
		lo, hi := max(address, word)-word, min(end, word+8)-word
		m.storageBadParity9020[word] |= byte(0xff >> lo & (0xff << (8 - hi)))
	}
}

func (m *Machine) clearStorageDataParity9020(address, size uint32) {
	if len(m.storageBadParity9020) == 0 || size == 0 {
		return
	}
	end := address + size
	for word, mask := range m.storageBadParity9020 {
		lo, hi := max(address, word), min(end, word+8)
		if lo >= hi {
			continue
		}
		mask &^= byte(0xff >> (lo - word) & (0xff << (word + 8 - hi)))
		if mask == 0 {
			delete(m.storageBadParity9020, word)
		} else {
			m.storageBadParity9020[word] = mask
		}
	}
}

func (m *Machine) firstBadDataWord9020(address, size uint32) (uint32, bool) {
	if len(m.storageBadParity9020) == 0 || size == 0 {
		return 0, false
	}
	width := m.storageWordSize9020()
	first, end := address&^(width-1), address+size
	failed := end
	for word, bad := range m.storageBadParity9020 {
		if width == 4 {
			if bad&0xf0 != 0 && word >= first && word < failed {
				failed = word
			}
			if bad&0xf == 0 {
				continue
			}
			word += 4
		}
		if word >= first && word < failed {
			failed = word
		}
	}
	return failed, failed < end
}

func (m *Machine) storageWordSize9020() uint32 {
	if m.cfg.Model9020A {
		return 4
	}
	return 8
}

func (c *CPU) storeKeyParity9020(address uint32) {
	m := c.M
	block := address >> c.S.KeyShift
	if !c.maintenance9020.reverseSumParity {
		delete(m.storageBadKey9020, block)
		return
	}
	if m.storageBadKey9020 == nil {
		m.storageBadKey9020 = make(map[uint32]bool)
	}
	m.storageBadKey9020[block] = true
}

// SSK can send bad parity on its incoming bus. ISK and storage
// protection lookups check the parity of the saved key.
func (c *CPU) storageKeyCheck9020(address uint32, operation uint16, incoming bool) {
	m := c.M
	if !incoming && !m.storageBadKey9020[address>>c.S.KeyShift] {
		return
	}
	m.recordStorage9020(address, 1, accFetch, 0x80>>c.Addr, c.PSW.Key, 0)
	cycle := &m.storageLatches9020[address/m.storageElementSize9020()][address>>3&1]
	cycle.Operation |= operation
	if incoming {
		cycle.InputKey = cycle.StoredKey
		cycle.Marks = 0xff
		cycle.BadInputKeyParity = true
	} else {
		cycle.BadStoredKeyParity = true
	}
	c.storageCheck9020(address, 0x10)
}

func (c *CPU) latchStorage9020(address, size uint32, acc access) {
	m := c.M
	if !m.Model9020 || m.cfg.IOCE || c.Addr >= 4 || address/m.storageElementSize9020() >= uint32(m.storageSlots9020()) {
		return
	}
	if acc != accStore && m.isDisplayAddress9020(address) {
		c.accessDisplayStorage9020E(address, size)
	}
	response := byte(0x80 >> c.Addr)
	var flags storageCycleFlags9020
	if !c.PSW.MC {
		flags = ignoreStorageCheck9020
	}
	if acc == accStore {
		if c.maintenance9020.reverseSumParity {
			flags |= badSumParity9020
		}
	} else {
		if flags := c.maintenance9020.reverseAddressParity; flags != 0 && size != 0 {
			m.recordStorage9020(address, min(size, 8-address&7), acc, response, c.PSW.Key, flags)
			c.storageCheck9020(address, 0x10)
			return
		}
		if failed, bad := m.firstBadDataWord9020(address, size); bad {
			throughFailure := min(address+size, failed+m.storageWordSize9020()) - address
			m.recordStorage9020(address, throughFailure, acc, response, c.PSW.Key, flags)
			c.storageDataCheck9020(failed)
			address += throughFailure
			size -= throughFailure
		}
	}
	m.recordStorage9020(address, size, acc, response, c.PSW.Key, flags)
}

// Bad address or mark parity cancels the write and regenerates the existing
// word. The storage latches retain the requested marks and bad bus parity.
func (c *CPU) cancelStorageWrite9020(address, size uint32) bool {
	if c.M.isDisplayAddress9020(address) && !c.M.cfg.IOCE && c.Addr < 4 {
		c.accessDisplayStorage9020E(address, size)
	}
	flags := c.maintenance9020.reverseAddressParity
	if c.maintenance9020.reverseMarkParity {
		flags |= badMarkParity9020
	}
	if flags == 0 || size == 0 {
		return false
	}
	first := min(size, 8-address&7)
	c.M.recordStorage9020(address, first, accStore, 0x80>>c.Addr, c.PSW.Key, flags)
	c.storageCheck9020(address, 0x10) // CE logword 42, SE/DE Address Check.
	return true
}

func (s *ChannelSubsystem) latchIOCEStorage9020(devno uint16, address, size uint32, acc access, key byte) {
	ioce := devno >> 10
	if !s.m.Model9020 || s.m.cfg.IOCE || ioce >= 3 || s.machAddress(address) {
		return
	}
	s.m.recordStorage9020(address, size, acc, 0x04>>ioce, key, 0)
}

func (s *ChannelSubsystem) ioceMachineCheckPending9020(devno uint16) bool {
	id := devno >> 10
	return s.m.Model9020 && id < 3 && s.ioceChecks9020[id].Check.Pending
}

func (s *ChannelSubsystem) checkIOCECCW9020(ce *CPU, devno uint16, address uint32, key byte) bool {
	return s.checkIOCEKey9020(ce.Addr, devno, address, 4, accFetch, key) ||
		s.checkIOCEFetch9020(ce, devno, address, key) ||
		s.m.cfg.Model9020A && s.checkIOCEFetch9020(ce, devno, address+4, key)
}

// Each CCW is fetched as two IOCE word cycles. The SE checks the full
// doubleword on the first 9020D/E cycle, and just the addressed word
// on the 9020A. The IOCE checks the returned word.
func (s *ChannelSubsystem) checkIOCEFetch9020(ce *CPU, devno uint16, address uint32, key byte) bool {
	m := s.m
	id := devno >> 10
	if !m.Model9020 || m.cfg.IOCE || id >= 3 || address/m.storageElementSize9020() >= uint32(m.storageSlots9020()) {
		return false
	}
	parity := m.storageBadParity9020[address&^7]
	badBytes := parity >> (4 - (address & 4)) & 0x0f
	if m.cfg.Model9020A && badBytes == 0 {
		return false
	}
	if parity == 0 {
		return false
	}
	return s.reportIOCEStorageCheck9020(ce, devno, address, 4, accFetch, key, 0, badBytes)
}

func (s *ChannelSubsystem) checkIOCEKey9020(ceAddr uint16, devno uint16, address, size uint32, acc access, key byte) bool {
	m := s.m
	id := devno >> 10
	if len(m.storageBadKey9020) == 0 || m.cfg.IOCE || id >= 3 || int(ceAddr) >= len(m.CPUs) ||
		s.machAddress(address) || address/m.storageElementSize9020() >= uint32(m.storageSlots9020()) ||
		!m.storageBadKey9020[address>>m.S.KeyShift] {
		return false
	}
	// A channel storage cycle addresses one word, even on a doubleword SE.
	size = min(size, 4-address&3)
	var badBytes byte
	if acc == accFetch {
		badBytes = m.storageBadParity9020[address&^7] >> (4 - (address & 4)) & 0xf
	}
	return s.reportIOCEStorageCheck9020(m.CPUs[ceAddr], devno, address, size, acc, key, badStoredKeyParity9020, badBytes)
}

func (s *ChannelSubsystem) reportIOCEStorageCheck9020(ce *CPU, devno uint16, address, size uint32, acc access, key byte, flags storageCycleFlags9020, badBytes byte) bool {
	m := s.m
	id := devno >> 10
	ioce := &s.ioceChecks9020[id]
	if ioce.Check.Pending {
		return true
	}
	m.recordStorage9020(address, size, acc, 0x04>>id, key, flags)
	se := int(address/m.storageElementSize9020()) + 1
	ioce.CE = ce.Addr
	ioce.Check = machineCheck9020{Pending: true, Element: id + 1}
	logout := &ioce.Check.Logout
	// Design Data figure 5-5, word 88: the SE access request lines.
	be.PutUint32(logout[ioceSERequest9020:], uint32(0x80000000)>>(se-1))
	logout[ioceStorageCheck9020] = 0x10 // SE storage check.
	// An uninhibited IOCE issues LOS before waiting for the CE's
	// machine-check mask (IBM 9020D System FETOM, pp. 8-4 and 8-16).
	if m.configuration9020[29+id].Word&inhibitLOS9020 == 0 {
		m.stopStorage9020(se, m.liveStorageLogout9020(se))
		logout[ioceStorageCheck9020] |= 0x04 // SE LOS.
	}
	if badBytes != 0 {
		logout[ioceStorageCheck9020] |= 0x02 // IOCE fetch data check.
		// Design Data figure 5-5, word 89, bits 5–8: full-sum checks.
		be.PutUint16(logout[ioceCheck1Offset9020:], uint16(badBytes)<<7)
	}
	ce.pswChanged = true
	return true
}

// The span is in one physical storage element. Only the last access to
// each bank survives in its storage registers.
func (m *Machine) recordStorage9020(address, size uint32, acc access, response, key byte, flags storageCycleFlags9020) {
	se := address / m.storageElementSize9020()
	if size == 0 || se >= uint32(m.storageSlots9020()) {
		return
	}
	if acc == accStore && flags&(badMarkParity9020|badAddressParity9020|badStoredKeyParity9020) == 0 {
		if flags&badSumParity9020 != 0 {
			m.markStorageDataParity9020(address, size)
		} else {
			m.clearStorageDataParity9020(address, size)
		}
		if m.isDisplayAddress9020(address) && address%m.storageElementSize9020() < 3 {
			m.stopDisplayCVGs9020E(int(se)+1, address, size)
		}
	}
	if m.cfg.Model9020A {
		m.recordStorage9020A(address, size, acc, response, key, flags&ignoreStorageCheck9020 != 0)
		return
	}
	end := address + size
	last := (end - 1) &^ 7
	first := address &^ 7
	if last > first {
		first = last - 8
	}
	for a := first; a <= last; a += 8 {
		lo, hi := max(address, a), min(end, a+8)
		busAddress := a
		if response&0x07 != 0 {
			// An IOCE cycle addresses a single word within the doubleword.
			// SAB bit 21 selects which half receives the byte stats.
			busAddress = (hi - 1) &^ 3
			lo = max(lo, busAddress)
		}
		cycle := &m.storageLatches9020[se][a>>3&1]
		*cycle = storageCycle9020{
			Data: be.Uint64(m.S.Mem[a:]), Address: busAddress % bytesPer9020SE,
			Response: response, Operation: seFetch9020,
			InputKey: key << 1, StoredKey: *m.S.key(a) >> 3,
			BadAddressParity:   flags & badAddressParity9020,
			BadStoredKeyParity: flags&badStoredKeyParity9020 != 0,
		}
		if len(m.storageBadParity9020) != 0 {
			cycle.BadDataParity = m.storageBadParity9020[a]
		}
		if acc == accStore {
			lo, hi = lo-a, hi-a
			cycle.Marks = byte(0xff >> lo & (0xff << (8 - hi)))
			cycle.Operation = seStore9020
			cycle.BadMarkParity = flags&badMarkParity9020 != 0
		}
	}
}

func oddParity9020(value byte) uint32 {
	return uint32(1 - bits.OnesCount8(value)%2)
}

// liveStorageLogout9020 packs the latch registers as Figure 12-5 specifies.
func (m *Machine) liveStorageLogout9020(id int) [seLogoutSize9020]byte {
	if m.cfg.Model9020A {
		return m.liveStorageLogout9020A(id)
	}
	if m.cfg.Model9020E && id > max9020EStorageElements {
		return m.liveDisplayLogout9020E(id)
	}
	var data [seLogoutSize9020]byte
	ccr := m.ccr9020(7 + uint32(id))
	comm := byte((ccr&ceMask9020)>>4 | ccr&ioceMask9020)
	controls := byte(ccr >> 24)
	cycles := &m.storageLatches9020[id-1]
	// The SE has one protection circuit. Its register contents are logged
	// with the odd bank even if the failing access was to the even bank.
	protect := cycles[1]
	if cycles[0].BadInputKeyParity || cycles[0].BadStoredKeyParity || cycles[0].BadAddressParity&badAddressPA9020 != 0 {
		protect = cycles[0]
	}
	for bank, cycle := range cycles {
		words := data[bank*24:]
		be.PutUint64(words, cycle.Data)
		tag := uint32(0)
		if cycle.Operation != 0 {
			tag = uint32(id)<<1 | cycle.Address>>18
		}
		sar := cycle.Address >> 4 & 0x3fff
		be.PutUint32(words[8:], uint32(cycle.Marks)<<24|tag<<18|sar<<4)
		response := uint32(cycle.Response) << 8
		operation := uint32(cycle.Operation &^ seCommonOp9020)
		var parity uint32
		if cycle.Operation != 0 {
			operation |= oddParity9020(cycle.Marks)<<3 | oddParity9020(byte(tag))<<2 |
				oddParity9020(byte(sar>>7))<<1 | oddParity9020(byte(sar&0x7f))
			for i := range 8 {
				parity = parity<<1 | oddParity9020(byte(cycle.Data>>(56-8*i)))
			}
			if cycle.BadDataParity != 0 {
				parity ^= uint32(cycle.BadDataParity)
				parity |= seDataParityCheck9020
			}
			if cycle.BadMarkParity {
				operation ^= 1 << 3
				parity |= seMarkParityCheck9020
			}
			if cycle.BadAddressParity != 0 {
				operation ^= uint32(cycle.BadAddressParity)
				parity |= seAddrParityCheck9020
			}
			if cycle.BadInputKeyParity || cycle.BadStoredKeyParity || cycle.BadAddressParity&badAddressPA9020 != 0 {
				parity |= seSPParityCheck9020
			}
			if cycle.Response&0x07 != 0 {
				// IOCE SAB parity P0–P2, one bit per address byte.
				address := uint32(id)<<19 | cycle.Address
				for i := range 3 {
					operation |= oddParity9020(byte(address>>(16-8*i))) << (6 - i)
				}
			}
		}
		if bank == 0 {
			response |= uint32(comm)<<24 | uint32(controls)
			operation |= uint32(id) << 19
			operation |= uint32(protect.Operation & seCommonOp9020)
			parity |= oddParity9020(controls)<<9 | oddParity9020(comm)<<8
		} else if protect.Operation != 0 {
			inputParity, storedParity := oddParity9020(protect.InputKey), oddParity9020(protect.StoredKey)
			if protect.BadInputKeyParity {
				inputParity ^= 1
			}
			if protect.BadStoredKeyParity {
				storedParity ^= 1
			}
			operation |= inputParity<<31 | uint32(protect.InputKey)<<26 |
				storedParity<<23 | uint32(protect.StoredKey)<<18
			protectAddr := byte(protect.Address >> 11)
			addressParity := oddParity9020(protectAddr)
			if protect.BadAddressParity&badAddressPA9020 != 0 {
				addressParity ^= 1
			}
			parity |= addressParity<<25 | uint32(protectAddr)<<17
		}
		be.PutUint32(words[12:], response)
		be.PutUint32(words[16:], operation)
		be.PutUint32(words[20:], parity)
	}
	return data
}
