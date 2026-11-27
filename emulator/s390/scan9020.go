package s390

// The scanned R halfword precedes the Q doubleword. The first halfword
// in Q completes the prefetched RX instruction in R.
type scanPrefetch9020 struct {
	Active  bool
	Address uint32
	Bytes   [10]byte
}

// 7201-02 FEMDM diagrams 5-609 and 6-116. Partial scan-in brings a
// 64-byte frame from the PSA into the CE. B13 accepts the MCW in ST/B
// with the I2 field from E. The supported End Op continuation takes
// the prefetched RX instruction from R and its remaining bytes from Q.
func (c *CPU) partialScan9020(mcw uint64) {
	const controls = 0x0000080000008000 // Disable interval timer and Diagnose SE 1.
	if !c.stateZero9020() || mcw&^controls != 0x006b000000000000 {
		c.program(pgmSpecification)
	}
	var frame [64]byte
	for i := uint32(0); i < uint32(len(frame)); i += 8 {
		be.PutUint64(frame[i:], c.fetchDouble(0x80+i, 0))
	}
	continuation := be.Uint32(frame[12:16])
	e, r := be.Uint16(frame[56:58]), be.Uint16(frame[58:60])
	ic := be.Uint32(frame[52:56])
	if continuation>>12&0xfff != 0xb13 || byte(e>>8) != 0x83 || r>>14 != 1 || ic&7 != 6 {
		c.program(pgmSpecification)
	}
	mode := c.diagInterleave9020(byte(e))
	inner := uint64(be.Uint32(frame[0:4]))<<32 | uint64(be.Uint32(frame[32:36]))
	c.endOpMCW9020(inner)
	c.setInterleave9020(mode)
	// IC points beyond the doubleword in Q. R begins two bytes before Q.
	addr := (ic - 16) & c.amask
	psw := uint64(be.Uint32(frame[48:52]))<<32 | uint64(ic&0x0f000000|addr)
	c.loadPSW(psw)
	c.next = addr
	c.pswChanged = true
	prefetch := scanPrefetch9020{Active: true, Address: addr}
	be.PutUint16(prefetch.Bytes[:2], r)
	copy(prefetch.Bytes[2:], frame[16:24])
	c.maintenance9020.scanPrefetch = prefetch
}

func (c *CPU) fetchScannedInstruction9020(ia uint32) uint32 {
	q := &c.maintenance9020.scanPrefetch
	if !q.Active {
		return 0
	}
	off := (ia - q.Address) & c.amask
	if off >= uint32(len(q.Bytes)) {
		q.Active = false
		return 0
	}
	n := ilen(q.Bytes[off])
	for i := uint32(0); i < n; i++ {
		if off+i < uint32(len(q.Bytes)) {
			c.op[i] = q.Bytes[off+i]
		} else {
			c.op[i] = c.fetchInstrByte(ia + i)
		}
	}
	return n
}
