package main

import "renvo.dev/device/dos"

type platformRegisters = dos.Registers

const pingReply = "OK\tsDOS extension v1\n"
const programOperation = "run"

var serialRegs dos.Registers

func writeByte(value byte) {
	serialRegs.AX = 0x0100 | uint16(value)
	serialRegs.DX = 0
	interrupt14(&serialRegs)
}
func configureSerial() { serialRegs.AX = 0xe3; serialRegs.DX = 0; interrupt14(&serialRegs) }
func readByte() {
	serialRegs.AX = 0x0200
	serialRegs.DX = 0
	interrupt14(&serialRegs)
}

func fileCall(ax, bx, cx, dx uint16) { dosCall(ax, bx, cx, dx) }

var tail [128]byte
var params [14]byte
var fcb [37]byte
var psp uint16

func putWord(offset int, value uint16) {
	params[offset] = byte(value)
	params[offset+1] = byte(value >> 8)
}
func runProgram() {
	if fields != 4 || !stringArg(2, 127, false) || !stringArg(3, 126, true) {
		bad()
		return
	}
	for i := 0; i < len(used); i++ {
		if used[i] {
			send("ERR\tsbusy\tsClose all files before running a child\n")
			return
		}
	}
	n := ends[3] - starts[3] - 1
	tail[0] = byte(n)
	for i := 0; i < n; i++ {
		tail[i+1] = input[starts[3]+1+i]
	}
	tail[n+1] = 13
	putWord(0, 0) // Inherit environment.
	putWord(2, pointer(&tail[0]))
	putWord(4, psp)
	putWord(6, pointer(&fcb[0]))
	putWord(8, psp)
	putWord(10, pointer(&fcb[0]))
	putWord(12, psp)
	dosCall(0x4b00, pointer(&params[0]), 0, argPointer(2))
	// DOS 3+ preserves the parent stack/registers; supported baseline is DOS 5+.
	configureSerial()
	finding = false
	if failed(&regs) {
		return
	}
	dosCall(0x4d00, 0, 0, 0)
	send("OK\tm2\tsexit_code\ti")
	sendInt(regs.AX & 255)
	send("\tstermination\ti")
	sendInt(regs.AX >> 8)
	send("\n")
}
func main() {
	dosCall(0x3000, 0, 0, 0)
	if regs.AX&255 < 5 {
		return
	}
	dosCall(0x6200, 0, 0, 0)
	psp = regs.BX
	// This is a COM program. Keep its complete 64 KiB segment including stack,
	// and return the remainder of the initial DOS allocation for child programs.
	regs.AX = 0x4a00
	regs.BX = 4096
	regs.ES = psp
	interrupt21ES(&regs)
	if regs.Flags&dos.FlagCarry != 0 {
		return
	}
	configureSerial()
	for {
		n := 0
		overflow := false
		for {
			readByte()
			c := byte(serialRegs.AX)
			if serialRegs.AX&0x8000 != 0 {
				continue
			}
			if c == 10 {
				break
			}
			if n < lineLimit {
				input[n] = c
				n++
			} else {
				overflow = true
			}
		}
		if overflow || !parse(n) {
			bad()
		} else {
			dispatch()
		}
	}
}
