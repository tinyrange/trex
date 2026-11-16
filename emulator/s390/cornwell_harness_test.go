package s390

import (
	"testing"
	"time"
)

// These test-only bindings run the Cornwell/Shirriff vectors directly on our
// CPU and storage. They contain no upstream instruction implementation.
type cornwellFixture struct {
	t    *testing.T
	m    *Machine
	c    *CPU
	trap bool
}

const (
	LMASKL uint64 = 0x00000000ffffffff
	HMASKL uint64 = 0xffffffff00000000
	MSIGNL uint64 = 0x8000000000000000
	MMASKL uint64 = 0x00ffffffffffffff
	FMASK  uint32 = 0xffffffff
)

func (h *cornwellFixture) setup() {
	if h.m == nil {
		h.m = NewMachine(Config{Memory: 64 << 10, S370: true, Start: time.Date(1985, 8, 30, 12, 0, 0, 0, time.UTC)})
	}
	h.c = h.m.CPUs[0]
	h.c.Reset(true)
	h.c.Stopped = false
	h.c.PSW.CC = 3
}

// Upstream word helpers select the containing aligned word and update the
// reference/change bits, even when used to arrange or inspect a fixture.
func (h *cornwellFixture) setMemory(a, v uint32) {
	be.PutUint32(h.m.S.Mem[a&^3:], v)
	*h.m.S.key(a) |= keyRef | keyChg
	h.c.ipageValid = false
}
func (h *cornwellFixture) getMemory(a uint32) uint32 {
	*h.m.S.key(a) |= keyRef
	return be.Uint32(h.m.S.Mem[a&^3:])
}
func (h *cornwellFixture) setByte(a, v uint32) {
	h.m.S.Mem[a] = byte(v)
	*h.m.S.key(a) |= keyRef | keyChg
}
func (h *cornwellFixture) getByte(a uint32) byte {
	*h.m.S.key(a) |= keyRef
	return h.m.S.Mem[a]
}
func (h *cornwellFixture) putKey(a uint32, k byte) {
	*h.m.S.key(a) = k
	h.m.keyGen++
	h.c.ipageValid = false
}
func (h *cornwellFixture) getKey(a uint32) byte { return *h.m.S.key(a) }

// Upstream exposes an expanded 16-channel I/O mask. BC PSW bit 6
// enables channels 6 through 15; bit 7 separately enables external interrupts.
func (h *cornwellFixture) channelMask() uint16 {
	mask := uint16(h.c.PSW.SysMask&0xfc) << 8
	if h.c.PSW.SysMask&2 != 0 {
		mask |= 0x3ff
	}
	return mask
}

// Match upstream's bounded instruction driver: begin at 0x400, recognize
// the program-new PSW at 0x800, and stop before the zero-halfword sentinel.
// Use the production run loop so exception delivery and stored PSWs are tested.
func (h *cornwellFixture) testInst(mask byte) {
	h.t.Helper()
	h.c.PSW.IA = 0x400
	h.c.PSW.ProgMask = mask & 15
	// The upstream fixture exposes Ext separately from its I/O mask.
	h.c.PSW.SysMask = h.c.PSW.SysMask&0xfe | b2(h.c.PSW.Ext)
	h.c.ipageValid = false
	h.setMemory(0x68, 0)
	h.setMemory(0x6c, 0x800)
	h.trap = false
	for range 20 {
		h.m.Run(1)
		if h.c.Check || h.c.Stopped {
			h.t.Fatalf("CPU stopped: %s", h.c.checkReason)
		}
		if h.c.PSW.IA == 0x800 {
			h.trap = true
		}
		if be.Uint16(h.m.S.Mem[h.c.PSW.IA:]) == 0 {
			return
		}
	}
	h.t.Fatalf("instruction fixture exceeded 20 instructions at %06x", h.c.PSW.IA)
}

func TestCornwellS370(t *testing.T) {
	tests := []struct {
		name string
		run  func(*cornwellFixture, *testing.T)
	}{
		{"TestFloatConv", (*cornwellFixture).TestFloatConv},
		{"TestShortConv", (*cornwellFixture).TestShortConv},
		{"TestLongConv", (*cornwellFixture).TestLongConv},
		{"TestRandFloat", (*cornwellFixture).TestRandFloat},
		{"TestCycleLR", (*cornwellFixture).TestCycleLR},
		{"TestCycleLTR", (*cornwellFixture).TestCycleLTR},
		{"TestCycleLCR", (*cornwellFixture).TestCycleLCR},
		{"TestCycleLPR", (*cornwellFixture).TestCycleLPR},
		{"TestCycleLNR", (*cornwellFixture).TestCycleLNR},
		{"TestCycleL", (*cornwellFixture).TestCycleL},
		{"TestCycleA", (*cornwellFixture).TestCycleA},
		{"TestCycleAH1", (*cornwellFixture).TestCycleAH1},
		{"TestCycleAL", (*cornwellFixture).TestCycleAL},
		{"TestCycleS", (*cornwellFixture).TestCycleS},
		{"TestCycleAH", (*cornwellFixture).TestCycleAH},
		{"TestCycleSH", (*cornwellFixture).TestCycleSH},
		{"TestCycleSL", (*cornwellFixture).TestCycleSL},
		{"TestCycleC", (*cornwellFixture).TestCycleC},
		{"TestCycleCL", (*cornwellFixture).TestCycleCL},
		{"TestCycleCH", (*cornwellFixture).TestCycleCH},
		{"TestCycleM", (*cornwellFixture).TestCycleM},
		{"TestCycleMH", (*cornwellFixture).TestCycleMH},
		{"TestCycleD", (*cornwellFixture).TestCycleD},
		{"TestCycleST", (*cornwellFixture).TestCycleST},
		{"TestCycleSTH", (*cornwellFixture).TestCycleSTH},
		{"TestCycleLH", (*cornwellFixture).TestCycleLH},
		{"TestCycleLA", (*cornwellFixture).TestCycleLA},
		{"TestCycleSTC", (*cornwellFixture).TestCycleSTC},
		{"TestCycleSIC", (*cornwellFixture).TestCycleSIC},
		{"TestCycleEX", (*cornwellFixture).TestCycleEX},
		{"TestCycleBAL", (*cornwellFixture).TestCycleBAL},
		{"TestCycleBALR", (*cornwellFixture).TestCycleBALR},
		{"TestCycleBCT", (*cornwellFixture).TestCycleBCT},
		{"TestCycleBCTR", (*cornwellFixture).TestCycleBCTR},
		{"TestCycleBC", (*cornwellFixture).TestCycleBC},
		{"TestCycleBCR", (*cornwellFixture).TestCycleBCR},
		{"TestCycleBXH", (*cornwellFixture).TestCycleBXH},
		{"TestCycleBXLE", (*cornwellFixture).TestCycleBXLE},
		{"TestCycleN", (*cornwellFixture).TestCycleN},
		{"TestCycleO", (*cornwellFixture).TestCycleO},
		{"TestCycleX", (*cornwellFixture).TestCycleX},
		{"TestCycleSLA", (*cornwellFixture).TestCycleSLA},
		{"TestCycleSLL", (*cornwellFixture).TestCycleSLL},
		{"TestCycleSRL", (*cornwellFixture).TestCycleSRL},
		{"TestCycleSRA", (*cornwellFixture).TestCycleSRA},
		{"TestCycleSRDL", (*cornwellFixture).TestCycleSRDL},
		{"TestCycleSLDL", (*cornwellFixture).TestCycleSLDL},
		{"TestCycleSRDA", (*cornwellFixture).TestCycleSRDA},
		{"TestCycleSLDA", (*cornwellFixture).TestCycleSLDA},
		{"TestCycleLM", (*cornwellFixture).TestCycleLM},
		{"TestCycleSTM", (*cornwellFixture).TestCycleSTM},
		{"TestCycleTM", (*cornwellFixture).TestCycleTM},
		{"TestCycleCVB", (*cornwellFixture).TestCycleCVB},
		{"TestCycleCVD", (*cornwellFixture).TestCycleCVD},
		{"TestCycleMVI", (*cornwellFixture).TestCycleMVI},
		{"TestCycleNI", (*cornwellFixture).TestCycleNI},
		{"TestCycleCLI", (*cornwellFixture).TestCycleCLI},
		{"TestCycleOI", (*cornwellFixture).TestCycleOI},
		{"TestCycleXI", (*cornwellFixture).TestCycleXI},
		{"TestCycleMVN", (*cornwellFixture).TestCycleMVN},
		{"TestCycleMVC", (*cornwellFixture).TestCycleMVC},
		{"TestCycleMVZ", (*cornwellFixture).TestCycleMVZ},
		{"TestCycleMVO", (*cornwellFixture).TestCycleMVO},
		{"TestCycleMVIN", (*cornwellFixture).TestCycleMVIN},
		{"TestCyclePACK", (*cornwellFixture).TestCyclePACK},
		{"TestCycleUNPK", (*cornwellFixture).TestCycleUNPK},
		{"TestCycleNC", (*cornwellFixture).TestCycleNC},
		{"TestCycleCLC", (*cornwellFixture).TestCycleCLC},
		{"TestCycleOC", (*cornwellFixture).TestCycleOC},
		{"TestCycleXC", (*cornwellFixture).TestCycleXC},
		{"TestCycleTR", (*cornwellFixture).TestCycleTR},
		{"TestCycleTRT", (*cornwellFixture).TestCycleTRT},
		{"TestCycleSPM", (*cornwellFixture).TestCycleSPM},
		{"TestCycleSSM", (*cornwellFixture).TestCycleSSM},
		{"TestCycleLPSW", (*cornwellFixture).TestCycleLPSW},
		{"TestCycleSVC", (*cornwellFixture).TestCycleSVC},
		{"TestCycleSSK", (*cornwellFixture).TestCycleSSK},
		{"TestCycleISK", (*cornwellFixture).TestCycleISK},
		{"TestCycleProt", (*cornwellFixture).TestCycleProt},
		{"TestCycleTS", (*cornwellFixture).TestCycleTS},
		{"TestCycleED", (*cornwellFixture).TestCycleED},
		{"TestCycleEDMK", (*cornwellFixture).TestCycleEDMK},
		{"TestCycleCLM", (*cornwellFixture).TestCycleCLM},
		{"TestCycleICM", (*cornwellFixture).TestCycleICM},
		{"TestCycleSTCM", (*cornwellFixture).TestCycleSTCM},
		{"TestCycleCLCL", (*cornwellFixture).TestCycleCLCL},
		{"TestCycleAP", (*cornwellFixture).TestCycleAP},
		{"TestCycleZAP", (*cornwellFixture).TestCycleZAP},
		{"TestCycleCP", (*cornwellFixture).TestCycleCP},
		{"TestCycleSP", (*cornwellFixture).TestCycleSP},
		{"TestCycleMP", (*cornwellFixture).TestCycleMP},
		{"TestCycleDP", (*cornwellFixture).TestCycleDP},
		{"TestCycleDecimalTest", (*cornwellFixture).TestCycleDecimalTest},
		{"TestCycleSTD", (*cornwellFixture).TestCycleSTD},
		{"TestCycleLD", (*cornwellFixture).TestCycleLD},
		{"TestCycleLCDR", (*cornwellFixture).TestCycleLCDR},
		{"TestCycleLPDR", (*cornwellFixture).TestCycleLPDR},
		{"TestCycleLNDR", (*cornwellFixture).TestCycleLNDR},
		{"TestCycleCD", (*cornwellFixture).TestCycleCD},
		{"TestCycleHD", (*cornwellFixture).TestCycleHD},
		{"TestCycleAD", (*cornwellFixture).TestCycleAD},
		{"TestCycleSD", (*cornwellFixture).TestCycleSD},
		{"TestCyclMD", (*cornwellFixture).TestCyclMD},
		{"TestCyclDD", (*cornwellFixture).TestCyclDD},
		{"TestCycleAW", (*cornwellFixture).TestCycleAW},
		{"TestCycleSW", (*cornwellFixture).TestCycleSW},
		{"TestCycleSTE", (*cornwellFixture).TestCycleSTE},
		{"TestCycleLE", (*cornwellFixture).TestCycleLE},
		{"TestCycleCE", (*cornwellFixture).TestCycleCE},
		{"TestCycleHE", (*cornwellFixture).TestCycleHE},
		{"TestCycleAE", (*cornwellFixture).TestCycleAE},
		{"TestCycleSE", (*cornwellFixture).TestCycleSE},
		{"TestCyclME", (*cornwellFixture).TestCyclME},
		{"TestCyclDE", (*cornwellFixture).TestCyclDE},
		{"TestCycleAU", (*cornwellFixture).TestCycleAU},
		{"TestCycleSU", (*cornwellFixture).TestCycleSU},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &cornwellFixture{t: t}
			h.setup()
			tc.run(h, t)
		})
	}
}
