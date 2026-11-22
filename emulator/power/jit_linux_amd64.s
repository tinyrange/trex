//go:build linux && amd64

#include "textflag.h"

// func jitCall(code uintptr, cpu, mem, ctx unsafe.Pointer)
//
// Native blocks use R15 = cpu, R14 = mem, R13 = ctx, R12 = ctx.gen and RBX =
// the cache hash multiplier (tlbHash), and
// clobber the other general registers. They use no stack beyond the
// return address pushed by CALL.
TEXT ·jitCall(SB), NOSPLIT, $48-32
	MOVQ BX, 0(SP)
	MOVQ R12, 8(SP)
	MOVQ R13, 16(SP)
	MOVQ R14, 24(SP)
	MOVQ R15, 32(SP)
	MOVQ code+0(FP), AX
	MOVQ cpu+8(FP), R15
	MOVQ mem+16(FP), R14
	MOVQ ctx+24(FP), R13
	MOVQ 40(R13), R12
	MOVQ $0x9e3779b97f4a7c15, BX
	CALL AX
	MOVQ 0(SP), BX
	MOVQ 8(SP), R12
	MOVQ 16(SP), R13
	MOVQ 24(SP), R14
	MOVQ 32(SP), R15
	RET
