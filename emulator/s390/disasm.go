package s390

import "fmt"

// Instruction formats used by the disassembler.
const (
	fRR  = iota
	fRRm // mask, register (BCR)
	fRR1 // one register (SPM)
	fI   // SVC
	fRX
	fRXm // BC
	fRS
	fRS1 // R1,D2(B2) (shifts)
	fRSm // R1,M3,D2(B2)
	fSI
	fS
	fSS1 // D1(L,B1),D2(B2)
	fSS2 // D1(L1,B1),D2(L2,B2)
	fSSr // R1,R3 move with key
	fRRE
	fRRE1
	fRI
	fRIm // BRC
	fRSI
	fE
	fSSE
	fRXE
)

type opInfo struct {
	name string
	f    int
}

var ops1 = map[byte]opInfo{
	0x04: {"SPM", fRR1}, 0x05: {"BALR", fRR}, 0x06: {"BCTR", fRR}, 0x07: {"BCR", fRRm}, 0x0a: {"SVC", fI},
	0x0b: {"BSM", fRR}, 0x0c: {"BASSM", fRR}, 0x0d: {"BASR", fRR}, 0x0e: {"MVCL", fRR}, 0x0f: {"CLCL", fRR},
	0x10: {"LPR", fRR}, 0x11: {"LNR", fRR}, 0x12: {"LTR", fRR}, 0x13: {"LCR", fRR}, 0x14: {"NR", fRR},
	0x15: {"CLR", fRR}, 0x16: {"OR", fRR}, 0x17: {"XR", fRR}, 0x18: {"LR", fRR}, 0x19: {"CR", fRR},
	0x1a: {"AR", fRR}, 0x1b: {"SR", fRR}, 0x1c: {"MR", fRR}, 0x1d: {"DR", fRR}, 0x1e: {"ALR", fRR}, 0x1f: {"SLR", fRR},
	0x28: {"LDR", fRR}, 0x38: {"LER", fRR},
	0x40: {"STH", fRX}, 0x41: {"LA", fRX}, 0x42: {"STC", fRX}, 0x43: {"IC", fRX}, 0x44: {"EX", fRX},
	0x45: {"BAL", fRX}, 0x46: {"BCT", fRX}, 0x47: {"BC", fRXm}, 0x48: {"LH", fRX}, 0x49: {"CH", fRX},
	0x4a: {"AH", fRX}, 0x4b: {"SH", fRX}, 0x4c: {"MH", fRX}, 0x4d: {"BAS", fRX}, 0x4e: {"CVD", fRX},
	0x4f: {"CVB", fRX}, 0x50: {"ST", fRX}, 0x51: {"LAE", fRX}, 0x54: {"N", fRX}, 0x55: {"CL", fRX},
	0x56: {"O", fRX}, 0x57: {"X", fRX}, 0x58: {"L", fRX}, 0x59: {"C", fRX}, 0x5a: {"A", fRX},
	0x5b: {"S", fRX}, 0x5c: {"M", fRX}, 0x5d: {"D", fRX}, 0x5e: {"AL", fRX}, 0x5f: {"SL", fRX},
	0x60: {"STD", fRX}, 0x68: {"LD", fRX}, 0x70: {"STE", fRX}, 0x71: {"MS", fRX}, 0x78: {"LE", fRX},
	0x80: {"SSM", fS}, 0x82: {"LPSW", fS}, 0x83: {"DIAG", fRS}, 0x84: {"BRXH", fRSI}, 0x85: {"BRXLE", fRSI},
	0x86: {"BXH", fRS}, 0x87: {"BXLE", fRS}, 0x88: {"SRL", fRS1}, 0x89: {"SLL", fRS1}, 0x8a: {"SRA", fRS1},
	0x8b: {"SLA", fRS1}, 0x8c: {"SRDL", fRS1}, 0x8d: {"SLDL", fRS1}, 0x8e: {"SRDA", fRS1}, 0x8f: {"SLDA", fRS1},
	0x90: {"STM", fRS}, 0x91: {"TM", fSI}, 0x92: {"MVI", fSI}, 0x93: {"TS", fS}, 0x94: {"NI", fSI},
	0x95: {"CLI", fSI}, 0x96: {"OI", fSI}, 0x97: {"XI", fSI}, 0x98: {"LM", fRS}, 0x99: {"TRACE", fRS},
	0x9a: {"LAM", fRS}, 0x9b: {"STAM", fRS}, 0xa8: {"MVCLE", fRS}, 0xa9: {"CLCLE", fRS},
	0xac: {"STNSM", fSI}, 0xad: {"STOSM", fSI}, 0xae: {"SIGP", fRS}, 0xaf: {"MC", fSI}, 0xb1: {"LRA", fRX},
	0xb6: {"STCTL", fRS}, 0xb7: {"LCTL", fRS}, 0xba: {"CS", fRS}, 0xbb: {"CDS", fRS},
	0xbd: {"CLM", fRSm}, 0xbe: {"STCM", fRSm}, 0xbf: {"ICM", fRSm},
	0xd1: {"MVN", fSS1}, 0xd2: {"MVC", fSS1}, 0xd3: {"MVZ", fSS1}, 0xd4: {"NC", fSS1}, 0xd5: {"CLC", fSS1},
	0xd6: {"OC", fSS1}, 0xd7: {"XC", fSS1}, 0xd9: {"MVCK", fSSr}, 0xda: {"MVCP", fSSr}, 0xdb: {"MVCS", fSSr},
	0xdc: {"TR", fSS1}, 0xdd: {"TRT", fSS1}, 0xde: {"ED", fSS1}, 0xdf: {"EDMK", fSS1}, 0xe8: {"MVCIN", fSS1},
	0xf0: {"SRP", fSS2}, 0xf1: {"MVO", fSS2}, 0xf2: {"PACK", fSS2}, 0xf3: {"UNPK", fSS2}, 0xf8: {"ZAP", fSS2},
	0xf9: {"CP", fSS2}, 0xfa: {"AP", fSS2}, 0xfb: {"SP", fSS2}, 0xfc: {"MP", fSS2}, 0xfd: {"DP", fSS2},
}

var opsB2 = map[byte]opInfo{
	0x02: {"STIDP", fS}, 0x04: {"SCK", fS}, 0x05: {"STCK", fS}, 0x06: {"SCKC", fS}, 0x07: {"STCKC", fS},
	0x08: {"SPT", fS}, 0x09: {"STPT", fS}, 0x0a: {"SPKA", fS}, 0x0b: {"IPK", fS}, 0x0d: {"PTLB", fS},
	0x10: {"SPX", fS}, 0x11: {"STPX", fS}, 0x12: {"STAP", fS}, 0x14: {"SIE", fS}, 0x18: {"PC", fS},
	0x19: {"SAC", fS}, 0x20: {"SERVC", fRRE}, 0x21: {"IPTE", fRRE}, 0x22: {"IPM", fRRE1}, 0x23: {"IVSK", fRRE},
	0x24: {"IAC", fRRE1}, 0x25: {"SSAR", fRRE1}, 0x26: {"EPAR", fRRE1}, 0x27: {"ESAR", fRRE1}, 0x29: {"ISKE", fRRE},
	0x2a: {"RRBE", fRRE}, 0x2b: {"SSKE", fRRE}, 0x2c: {"TB", fRRE}, 0x30: {"CSCH", fS}, 0x31: {"HSCH", fS},
	0x32: {"MSCH", fS}, 0x33: {"SSCH", fS}, 0x34: {"STSCH", fS}, 0x35: {"TSCH", fS}, 0x36: {"TPI", fS},
	0x37: {"SAL", fS}, 0x38: {"RSCH", fS}, 0x39: {"STCRW", fS}, 0x3a: {"STCPS", fS}, 0x3b: {"RCHP", fS},
	0x3c: {"SCHM", fS}, 0x40: {"BAKR", fRRE}, 0x41: {"CKSM", fRRE}, 0x46: {"STURA", fRRE}, 0x4b: {"LURA", fRRE},
	0x4d: {"CPYA", fRRE}, 0x4e: {"SAR", fRRE}, 0x4f: {"EAR", fRRE}, 0x50: {"CSP", fRRE}, 0x52: {"MSR", fRRE},
	0x54: {"MVPG", fRRE}, 0x55: {"MVST", fRRE}, 0x5d: {"CLST", fRRE}, 0x5e: {"SRST", fRRE}, 0x76: {"XSCH", fS},
	0x78: {"STCKE", fS}, 0x79: {"SACF", fS}, 0x7d: {"STSI", fS}, 0xb1: {"STFL", fS}, 0xb2: {"LPSWE", fS},
}

var opsA7 = map[byte]opInfo{
	0x0: {"TMH", fRI}, 0x1: {"TML", fRI}, 0x4: {"BRC", fRIm}, 0x5: {"BRAS", fRI}, 0x6: {"BRCT", fRI},
	0x8: {"LHI", fRI}, 0xa: {"AHI", fRI}, 0xc: {"MHI", fRI}, 0xe: {"CHI", fRI},
}

// Disassemble formats one instruction at address ia.
func Disassemble(b []byte, ia uint32) (string, int) {
	if len(b) < 2 {
		return "?", len(b)
	}
	n := int(ilen(b[0]))
	if len(b) < n {
		return "?", len(b)
	}
	var info opInfo
	ok := false
	switch b[0] {
	case 0xb2:
		info, ok = opsB2[b[1]]
	case 0xa7:
		info, ok = opsA7[b[1]&0xf]
	case 0xe5:
		switch b[1] {
		case 0x01:
			info, ok = opInfo{"TPROT", fSSE}, true
		case 0x0e:
			info, ok = opInfo{"MVCSK", fSSE}, true
		case 0x0f:
			info, ok = opInfo{"MVCDK", fSSE}, true
		}
	default:
		info, ok = ops1[b[0]]
	}
	if !ok {
		return fmt.Sprintf("DC X'%X'", b[:n]), n
	}
	r1, r2 := b[1]>>4, b[1]&0xf
	bd := func(hi, lo byte) string {
		d := int(hi&0xf)<<8 | int(lo)
		if hi>>4 == 0 {
			return fmt.Sprintf("X'%03X'", d)
		}
		return fmt.Sprintf("X'%03X'(%d)", d, hi>>4)
	}
	var ops string
	switch info.f {
	case fRR:
		ops = fmt.Sprintf("%d,%d", r1, r2)
	case fRRm:
		ops = fmt.Sprintf("%d,%d", r1, r2)
	case fRR1:
		ops = fmt.Sprintf("%d", r1)
	case fI:
		ops = fmt.Sprintf("%d", b[1])
	case fRX, fRXm:
		d := int(b[2]&0xf)<<8 | int(b[3])
		ops = fmt.Sprintf("%d,X'%03X'(%d,%d)", r1, d, r2, b[2]>>4)
	case fRS, fRSm:
		ops = fmt.Sprintf("%d,%d,%s", r1, r2, bd(b[2], b[3]))
	case fRS1:
		ops = fmt.Sprintf("%d,%s", r1, bd(b[2], b[3]))
	case fSI:
		ops = fmt.Sprintf("%s,X'%02X'", bd(b[2], b[3]), b[1])
	case fS:
		ops = bd(b[2], b[3])
	case fSS1:
		ops = fmt.Sprintf("%s(%d),%s", bd(b[2], b[3]), int(b[1])+1, bd(b[4], b[5]))
	case fSS2:
		ops = fmt.Sprintf("%s(%d),%s(%d)", bd(b[2], b[3]), int(r1)+1, bd(b[4], b[5]), int(r2)+1)
	case fSSr:
		ops = fmt.Sprintf("%s(%d),%s,%d", bd(b[2], b[3]), r1, bd(b[4], b[5]), r2)
	case fSSE:
		ops = fmt.Sprintf("%s,%s", bd(b[2], b[3]), bd(b[4], b[5]))
	case fRRE:
		ops = fmt.Sprintf("%d,%d", b[3]>>4, b[3]&0xf)
	case fRRE1:
		ops = fmt.Sprintf("%d", b[3]>>4)
	case fRI:
		ops = fmt.Sprintf("%d,%d", r1, int16(be.Uint16(b[2:])))
		if info.name == "BRAS" || info.name == "BRCT" {
			ops = fmt.Sprintf("%d,%08X", r1, ia+uint32(int32(int16(be.Uint16(b[2:])))*2))
		}
	case fRIm:
		ops = fmt.Sprintf("%d,%08X", r1, ia+uint32(int32(int16(be.Uint16(b[2:])))*2))
	case fRSI:
		ops = fmt.Sprintf("%d,%d,%08X", r1, r2, ia+uint32(int32(int16(be.Uint16(b[2:])))*2))
	}
	return fmt.Sprintf("%-6s %s", info.name, ops), n
}
