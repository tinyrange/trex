package power

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
)

// StateDigest hashes real memory, pointer tags, the instruction count, the
// time base and each CPU's architected registers and SLB. Equal digests from
// two runs of the same guest show that they reached the same state, which
// makes it a check for execution-engine changes that must not alter
// behaviour. Host caches and retained observations are excluded.
func (m *Machine) StateDigest() string {
	h := sha256.New()
	var buf []byte
	word := func(v uint64) { buf = binary.BigEndian.AppendUint64(buf, v) }
	word(m.instructions)
	word(m.TB())
	for _, c := range m.CPUs {
		for _, r := range c.GPR {
			word(r)
		}
		for _, r := range c.FPR {
			word(r)
		}
		for _, r := range c.VSR {
			word(r[0])
			word(r[1])
		}
		for _, r := range []uint64{uint64(c.CR), c.LR, c.CTR, c.XER, c.PC, c.MSR, c.FPSCR, uint64(c.VSCR),
			c.SRR0, c.SRR1, c.DAR, uint64(c.DSISR), uint64(c.decAt), c.Instructions, c.resAddr, uint64(c.resSize),
			c.ctrl, c.icOffset, c.vtbOffset, c.purrOffset, c.spurrOffset} {
			word(r)
		}
		buf = append(buf, b2u8(c.resValid), b2u8(c.Parked), b2u8(c.Waiting), b2u8(c.external))
		for _, r := range c.SPRG {
			word(r)
		}
		keys := make([]int, 0, len(c.SPR))
		for k := range c.SPR {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			word(uint64(k))
			word(c.SPR[k])
		}
		for _, e := range c.SLB {
			word(e.ESID)
			word(e.VSID)
			word(e.Flags)
			buf = append(buf, b2u8(e.Valid), e.B)
		}
	}
	h.Write(buf)
	for _, t := range m.tags {
		buf = binary.BigEndian.AppendUint64(buf[:0], t)
		h.Write(buf)
	}
	h.Write(m.Mem)
	return hex.EncodeToString(h.Sum(nil))
}

func b2u8(b bool) byte {
	if b {
		return 1
	}
	return 0
}
