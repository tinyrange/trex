package arm64

// Instruction classes retain the original ordered encoding matches. The cache
// is keyed by the freshly fetched word, so code writes cannot leave stale decode.
type instructionClass uint8

const (
	opUnknown instructionClass = iota
	opPairwise
	opVectorCompare
	opVectorCompareZero
	opDataCache
	opICacheAll
	opICacheAddress
	opVectorExtract
	opAddWide
	opVectorSum
	opShiftLong
	opAcquireRelease
	opVectorSingleStructure
	opVectorAddSub
	opVectorInsert
	opCSDB
	opReverseBits
	opAddLong
	opShiftNarrow
	opVectorEqual
	opClearExclusive
	opExclusive
	opMultiplyLong
	opMultiplyHigh
	opPointerAuthHint
	opVectorToGeneral
	opGeneralToVector
	opVectorStructures
	opVectorLogical
	opVectorDuplicate
	opTLBI
	opBarrier
	opAddressTranslate
	opDAIFImmediate
	opSystem
	opCurrentEL
	opVectorImmediate
	opNop
	opReturn
	opBranchReg
	opBranchLinkReg
	opBranchImmediate
	opBranchConditional
	opCompareBranch
	opTestBranch
	opAddress
	opMoveWide
	opAddSub
	opAddCarry
	opLogical
	opBitfield
	opExtract
	opConditionalCompare
	opConditionalSelect
	opCountLeadingZeros
	opReverseBytes
	opDataTwoSource
	opMultiplyAdd
	opLoadStorePair
	opLoadStore
	opLoadLiteral
)

type decodeEntry struct {
	word  uint32
	class instructionClass
}

func (c *CPU) decode(i uint32) instructionClass {
	if c.DisableDecodeCache {
		return classifyInstruction(i)
	}
	e := &c.decodeCache[(i^i>>10^i>>20)&1023]
	if e.word == i {
		return e.class
	}
	class := classifyInstruction(i)
	*e = decodeEntry{i, class}
	return class
}

func classifyInstruction(i uint32) instructionClass {
	switch {
	case i&0xbf20fc00 == 0x0e20bc00 || i&0x9f20f400 == 0x0e20a400: // ADDP and signed/unsigned MAXP/MINP
		return opPairwise
	case i&0x9f20fc00 == 0x0e203400 || i&0x9f20fc00 == 0x0e203c00: // CMGT/CMGE/CMHI/CMHS vector
		return opVectorCompare
	case i&0xbf3ffc00 == 0x0e20a800: // CMLT vector elements, zero
		return opVectorCompareZero
	case i&0xffffffe0 == 0xd50b7a20 || i&0xffffffe0 == 0xd50b7b20 || i&0xffffffe0 == 0xd50b7e20 || i&0xffffffe0 == 0xd5087620: // DC CVAC/CVAU/CIVAC/IVAC
		return opDataCache
	case i&0xffffffe0 == 0xd5087500 || i&0xffffffe0 == 0xd5087100: // IC IALLU/IALLUIS
		return opICacheAll
	case i&0xffffffe0 == 0xd50b7520: // IC IVAU
		return opICacheAddress
	case i&0xbfe0fc00 == 0x0e003c00 || i&0xbfe0fc00 == 0x0e002c00: // UMOV/SMOV vector lane to GPR
		return opVectorExtract
	case i&0x9f20dc00 == 0x0e201000: // SADDW/UADDW/SSUBW/USUBW
		return opAddWide
	case i&0xbf3ffc00 == 0x0e31b800: // ADDV
		return opVectorSum
	case i&0x9f80fc00 == 0x0f00a400: // SSHLL/USHLL, including SXTL/UXTL aliases
		return opShiftLong
	case i&0x3fbffc00 == 0x089ffc00: // LDAR/STLR, including byte and halfword forms
		return opAcquireRelease
	case i&0xbf000000 == 0x0d000000: // LD/ST single SIMD structure elements
		return opVectorSingleStructure
	case i&0x9f20fc00 == 0x0e208400: // ADD/SUB vector elements
		return opVectorAddSub
	case i&0xffe0fc00 == 0x4e001c00: // INS vector element from general register (MOV alias)
		return opVectorInsert
	case i == 0xd503229f: // CSDB: no speculative execution exists in this interpreter.
		return opCSDB
	case i&0x7ffffc00 == 0x5ac00000: // RBIT
		return opReverseBits
	case i&0x9f3ffc00 == 0x0e303800: // SADDLV/UADDLV
		return opAddLong
	case i&0xbf80fc00 == 0x0f008400: // SHRN/SHRN2
		return opShiftNarrow
	case i&0xbf20fc00 == 0x2e208c00 || i&0xbf3ffc00 == 0x0e209800: // CMEQ vector elements or zero
		return opVectorEqual
	case i&0xfffff0ff == 0xd503305f: // CLREX
		return opClearExclusive
	case i&0x3fa00000 == 0x08000000 && i>>10&31 == 31: // single-register exclusive load/store
		return opExclusive
	case i&0xff600000 == 0x9b200000: // SMADDL/UMADDL/SMSUBL/UMSUBL (and MUL aliases)
		return opMultiplyLong
	case i&0xffe0fc00 == 0x9b407c00 || i&0xffe0fc00 == 0x9bc07c00: // SMULH/UMULH
		return opMultiplyHigh
	case i == 0xd503237f || i == 0xd50323ff: // PACIBSP/AUTIBSP are HINTs without FEAT_PAuth.
		return opPointerAuthHint
	case i&0xfffffc00 == 0x9e660000 || i&0xfffffc00 == 0x1e260000: // FMOV general register from SIMD scalar
		return opVectorToGeneral
	case i&0xfffffc00 == 0x9e670000 || i&0xfffffc00 == 0x1e270000: // FMOV SIMD scalar from general register
		return opGeneralToVector
	case i&0xbf200000 == 0x0c000000: // SIMD multiple structures
		return opVectorStructures
	case i&0x9f20fc00 == 0x0e201c00: // vector logical operations and bit selection
		return opVectorLogical
	case i&0xbfe0fc00 == 0x0e000c00: // DUP vector elements from a general register
		return opVectorDuplicate
	case i&0xffffffe0 == 0xd5088700 || i&0xffffffe0 == 0xd50887e0 || i&0xffffffe0 == 0xd5088720 || i&0xffffffe0 == 0xd5088760 || i&0xffffffe0 == 0xd50887a0: // EL1 TLBI
		return opTLBI
	case i == 0xd5033fdf || i&0xfffff0ff == 0xd503309f || i&0xfffff0ff == 0xd50330bf:
		return opBarrier
	case i&0xffffffe0 == 0xd5087800 || i&0xffffffe0 == 0xd5087820: // AT S1E1R/W
		return opAddressTranslate
	case i&0xfffff0df == 0xd50340df: // MSR DAIFSet/DAIFClr,#imm4
		return opDAIFImmediate
	case i&0xffd00000 == 0xd5100000: // MRS/MSR system register
		return opSystem
	case i&0xffffffe0 == 0xd5384240: // MRS CurrentEL
		return opCurrentEL
	case i&0x9ff80c00 == 0x0f000400: // MOVI/MVNI and vector ORR/BIC immediate
		return opVectorImmediate
	case i == 0xd503201f: // NOP
		return opNop
	case i&0xfffffc1f == 0xd65f0000:
		return opReturn
	case i&0xfffffc1f == 0xd61f0000:
		return opBranchReg
	case i&0xfffffc1f == 0xd63f0000:
		return opBranchLinkReg
	case i&0x7c000000 == 0x14000000:
		return opBranchImmediate
	case i&0xff000010 == 0x54000000:
		return opBranchConditional
	case i&0x7e000000 == 0x34000000:
		return opCompareBranch
	case i&0x7e000000 == 0x36000000:
		return opTestBranch
	case i&0x1f000000 == 0x10000000:
		return opAddress
	case i&0x1f800000 == 0x12800000: // MOVN/MOVZ/MOVK
		return opMoveWide
	case i&0x1f000000 == 0x11000000 || i&0x1f000000 == 0x0b000000:
		return opAddSub
	case i&0x1fe0fc00 == 0x1a000000:
		return opAddCarry
	case i&0x1f000000 == 0x0a000000 || i&0x1f800000 == 0x12000000:
		return opLogical
	case i&0x1f800000 == 0x13000000: // SBFM/BFM/UBFM
		return opBitfield
	case i&0x1f800000 == 0x13800000:
		return opExtract
	case i&0x1fe00000 == 0x1a400000: // conditional compare, register or immediate
		return opConditionalCompare
	case i&0x1fe00000 == 0x1a800000: // conditional select
		return opConditionalSelect
	case i&0x7ffffc00 == 0x5ac01000: // CLZ
		return opCountLeadingZeros
	case i&0x7ffffc00 == 0x5ac00400 || i&0x7ffffc00 == 0x5ac00800 || i&0xfffffc00 == 0xdac00c00: // REV16/REV32/REV64
		return opReverseBytes
	case i&0x7fe00000 == 0x1ac00000:
		return opDataTwoSource
	case i&0x1fe00000 == 0x1b000000:
		return opMultiplyAdd
	case i&0x3a000000 == 0x28000000: // load/store pair
		return opLoadStorePair
	case i&0x3b000000 == 0x39000000 || i&0x3b000000 == 0x38000000:
		return opLoadStore
	case i&0x3b000000 == 0x18000000:
		return opLoadLiteral
	}
	return opUnknown
}
