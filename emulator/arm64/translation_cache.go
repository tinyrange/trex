package arm64

import "github.com/tinyrange/trex/emulator/cpu"

type translationEntry struct {
	virtual, physical, attributes uint64
	access                        cpu.Access
	valid                         bool
}

type translationCache struct {
	memory  *cpu.AddressSpace
	version uint64
	entries [256]translationEntry
}

// ClearTranslationCache also releases any retained physical address space.
func (c *CPU) ClearTranslationCache() { c.translations = translationCache{} }

func (c *CPU) cachedTranslate(ram *cpu.AddressSpace, address uint64, access cpu.Access) (uint64, uint64, error) {
	t := &c.translations
	version := ram.TrackedWriteVersion()
	if t.memory != ram || t.version != version {
		clear(t.entries[:])
		t.memory, t.version = ram, version
	}
	page := address >> 12
	e := &t.entries[(page^uint64(access)*61)&255]
	if e.valid && e.virtual == page && e.access == access {
		return e.physical | address&4095, e.attributes, nil
	}
	pa, attributes, err := c.walk(ram, address, access)
	if err == nil {
		*e = translationEntry{page, pa &^ 4095, attributes, access, true}
	}
	return pa, attributes, err
}
