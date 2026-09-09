package arm64

import "github.com/tinyrange/trex/emulator/cpu"

// InvalidateExclusive lets a debugger/device notify the CPU of a physical write.
func (c *CPU) InvalidateExclusive(address uint64, size int) {
	if size > 0 && c.exclusiveValid && address < c.exclusiveAddress+c.exclusiveSize && c.exclusiveAddress < address+uint64(size) {
		c.exclusiveValid = false
	}
}

type exclusiveMemory struct {
	cpu               *CPU
	virtual, physical cpu.Memory
}

func (m exclusiveMemory) CheckMemory(a uint64, n int, access cpu.Access) error {
	return m.virtual.CheckMemory(a, n, access)
}
func (m exclusiveMemory) ReadMemory(a uint64, b []byte, access cpu.Access) error {
	return m.virtual.ReadMemory(a, b, access)
}
func (m exclusiveMemory) WriteMemory(a uint64, b []byte) error {
	var spans []span
	for remaining := len(b); remaining > 0; {
		size := min(remaining, 4096-int(a&4095))
		pa, err := m.cpu.Translate(m.physical, a, cpu.Write)
		if err != nil {
			m.cpu.exclusiveValid = false
			return err
		}
		spans = append(spans, span{pa, size})
		a += uint64(size)
		remaining -= size
	}
	if err := m.virtual.WriteMemory(a-uint64(len(b)), b); err != nil {
		return err
	}
	for _, span := range spans {
		m.cpu.InvalidateExclusive(span.address, span.size)
	}
	return nil
}
