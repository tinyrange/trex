package machine

// The filter only rejects definite misses. Collisions still use the exact
// maps, with hooks taking precedence over imports. It is value-owned so a
// snapshot can add hooks independently, and every insertion updates it.
func dispatchBit(address uint64) uint16 {
	return uint16(address ^ address>>16 ^ address>>32 ^ address>>48)
}

func (m *Machine) markDispatch(address uint64) {
	bit := dispatchBit(address)
	m.dispatchFilter[bit/64] |= uint64(1) << (bit % 64)
}

func (m *Machine) mayDispatch(address uint64) bool {
	bit := dispatchBit(address)
	return m.dispatchFilter[bit/64]&(uint64(1)<<(bit%64)) != 0
}

func (m *Machine) setHook(address uint64, value hook) {
	if m.hooks == nil {
		m.hooks = make(map[uint64]hook)
	}
	m.hooks[address] = value
	m.markDispatch(address)
}
