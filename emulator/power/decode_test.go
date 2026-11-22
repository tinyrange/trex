package power

import (
	"encoding/binary"
	"math/rand"
	"strings"
	"testing"

	"golang.org/x/arch/ppc64/ppc64asm"
)

// Mnemonics the core implements (as spelled by ppc64asm, without record or
// overflow suffixes). Words the reference decoder assigns to one of these must
// never reach the illegal-instruction path.
var implemented = strings.Fields(`tdi twi mulli subfic cmpli cmpi addic addi addis bc sc b rlwimi rlwinm rlwnm
ori oris xori xoris andi andis rldicl rldicr rldic rldimi rldcl rldcr lwz lwzu lbz lbzu stw stwu stb stbu lhz lhzu lha lhau sth sthu
lmw stmw lfs lfsu lfd lfdu stfs stfsu stfd stfdu lq ld ldu lwa std stdu stq mcrf bclr bcctr rfid isync crand cror crxor crnand
crnor creqv crandc crorc isel sradi subfc addc mulhdu mulhwu subf mulhd mulhw neg subfe adde subfze addze subfme mulld addme mullw add
divdu divwu divd divw divdeu divde cmp cmpl tw td mfcr mfocrf mtcrf mtocrf mfmsr mtmsr mtmsrd mfspr mftb mtspr lwarx ldarx lbarx lharx lqarx
stwcx stdcx stbcx sthcx stqcx ldx ldux lwzx lwzux lbzx lbzux lhzx lhzux lhax lhaux lwax lwaux stdx stdux stwx stwux stbx stbux sthx sthux
lwbrx lhbrx ldbrx stwbrx sthbrx stdbrx lswi stswi lswx stswx slw sld srw srd sraw srad srawi cntlzw cntlzd cnttzw cnttzd popcntb popcntw
popcntd prtyd cmpb bpermd and andc nor eqv xor orc or nand extsh extsb extsw modud modsd moduw modsw setb dcbf dcbst dcbt dcbtst icbi sync
hwsync lwsync eieio dcbz slbmte slbie slbia slbmfee slbmfev slbfee tlbiel tlbsync msgsndp lvx lvxl lxvd2x lxvw4x lxvx stvx stvxl stxvd2x
stxvw4x stxvx lfsx lfsux lfdx lfdux stfsx stfsux stfdx stfdux fadds fsubs fmuls fdivs fmadds fmsubs fnmadds fnmsubs fcfids fdiv fsub fadd
fsqrt fsel fmul fmsub fmadd fnmsub fnmadd fcmpu fcmpo fcpsgn fmr fneg fabs fnabs frsp frim frip friz frin fctiwz fctiw fctiwu fctiwuz fctidz fctid fcfid fcfidu fctiduz mffs mtfsf mtfsb0 mtfsb1 mtfsfi mcrfs mtvsrd mfvsrd`)

func TestReferenceDecodedWordsAreImplemented(t *testing.T) {
	supported := map[string]bool{}
	for _, m := range implemented {
		supported[m] = true
	}
	rng := rand.New(rand.NewSource(1))
	missing := map[string]uint32{}
	m := NewMachine(Config{Memory: 1 << 20})
	c := m.CPUs[0]
	for i := 0; i < 400000; i++ {
		w := rng.Uint32()
		var b [8]byte
		binary.BigEndian.PutUint32(b[:], w)
		inst, err := ppc64asm.Decode(b[:4], binary.BigEndian)
		if err != nil || inst.Op == 0 {
			continue
		}
		op := strings.TrimRight(inst.Op.String(), ".")
		if strings.HasSuffix(op, "o") && supported[strings.TrimSuffix(op, "o")] {
			op = strings.TrimSuffix(op, "o")
		}
		if !supported[op] {
			continue
		}
		// Invalid forms the reference decoder accepts: odd quadword register
		// pairs and reserved system-call levels.
		po := w >> 26
		if (po == 56 || po == 62 && w&3 == 2) && (w>>21)&1 != 0 || po == 56 && (w>>21)&31 == (w>>16)&31 || po == 17 && (w>>5)&0x7f > 1 {
			continue
		}
		if po == 31 && ((w>>1)&1023 == 179 || (w>>1)&1023 == 51) && (w>>11)&31 != 0 { // reserved VSR move field
			continue
		}
		*c = CPU{m: m, SPR: map[int]uint64{}, MSR: MSRSF | MSRME | MSRFP | MSRVEC | MSRVSX, PC: 0x1000, decAt: 1 << 62}
		binary.BigEndian.PutUint32(m.Mem[0x1000:], w)
		m.Extension = func(_ *CPU, x uint32) (bool, error) {
			missing[op] = x
			return true, nil
		}
		c.Step()
	}
	for op, w := range missing {
		t.Errorf("%s (%08x) reached the extension handler", op, w)
	}
}
