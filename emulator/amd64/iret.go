package amd64

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/emulator/cpu"
)

// iretq admits only a same-selector CPL3 return in the flat, 48-bit user-mode
// execution model. There is no GDT, task switch, privilege transition or NMI
// model. In long mode all five stack slots are consumed even at the same CPL.
func (c *CPU) iretq(memory cpu.Memory) (uint64, error) {
	var frame [40]byte
	if err := memory.ReadMemory(c.registers[4], frame[:], cpu.Read); err != nil {
		return 0, err
	}
	ip := binary.LittleEndian.Uint64(frame[0:8])
	cs := binary.LittleEndian.Uint16(frame[8:10])
	flags := binary.LittleEndian.Uint64(frame[16:24])
	sp := binary.LittleEndian.Uint64(frame[24:32])
	ss := binary.LittleEndian.Uint16(frame[32:34])
	if cs != c.selectors[0] || ss != c.selectors[1] || cs&3 != 3 || ss&3 != 3 || cs&^uint16(3) == 0 || ss&^uint16(3) == 0 {
		return 0, fmt.Errorf("amd64: IRETQ requires unchanged non-null CPL3 CS/SS selectors")
	}
	canonical := func(v uint64) bool { return v>>47 == 0 || v>>47 == 0x1ffff }
	if !canonical(ip) || !canonical(sp) {
		return 0, fmt.Errorf("amd64: IRETQ noncanonical RIP/RSP")
	}
	const unsupported = uint64(1<<14 | 1<<17 | 1<<19 | 1<<20) // NT, VM, VIF, VIP
	if (flags|c.flags)&unsupported != 0 {
		return 0, fmt.Errorf("amd64: IRETQ task/virtualized flags are not implemented")
	}
	// IOPL is retained at CPL3. IF is writable only at IOPL3; RF, unlike
	// POPFQ, is restored. Reserved bits have their architectural fixed values.
	writable := uint64(1<<0 | 1<<2 | 1<<4 | 1<<6 | 1<<7 | 1<<8 | 1<<10 | 1<<11 | 1<<16 | 1<<18 | 1<<21)
	if c.flags>>12&3 == 3 {
		writable |= 1 << 9
	}
	c.flags = 2 | c.flags&uint64(3<<12|1<<9)&^writable | flags&writable
	c.registers[4] = sp
	return ip, nil
}
