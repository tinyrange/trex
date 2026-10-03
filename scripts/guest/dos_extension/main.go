package main

import (
	"renvo.dev/device/dos"
	"unsafe"
)

// Shared register blocks avoid escaping a fresh stack-local block on each byte.
var regs dos.Registers
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
func dosCall(ax, bx, cx, dx uint16) {
	regs.AX = ax
	regs.BX = bx
	regs.CX = cx
	regs.DX = dx
	interrupt21(&regs)
}

var digits [5]byte
var handles [8]uint16
var used [8]bool
var dta [43]byte
var finding bool
var tail [128]byte
var params [14]byte
var fcb [37]byte
var psp uint16

func pointer(data *byte) uint16   { return uint16(uintptr(unsafe.Pointer(data))) }
func argPointer(index int) uint16 { return pointer(&input[starts[index]+1]) }
func send(text string) {
	for i := 0; i < len(text); i++ {
		writeByte(text[i])
	}
}
func sendInt(n uint16) {
	pos := len(digits)
	for {
		pos--
		digits[pos] = byte(n%10) + '0'
		n /= 10
		if n == 0 {
			break
		}
	}
	for pos < len(digits) {
		writeByte(digits[pos])
		pos++
	}
}
func bad()                 { send("ERR\tsbad_call\tsInvalid arguments or unsupported call\n") }
func dosError(code uint16) { send("ERR\tsdos\tsDOS error "); sendInt(code); send("\n") }
func failed(regs *dos.Registers) bool {
	if regs.Flags&dos.FlagCarry != 0 {
		dosError(regs.AX)
		return true
	}
	return false
}
func okInt(n uint16) { send("OK\ti"); sendInt(n); send("\n") }
func pathOperation(ax uint16) {
	if fields != 3 || !stringArg(2, 127, false) {
		bad()
		return
	}
	dosCall(ax, 0, 0, argPointer(2))
	if !failed(&regs) {
		send("OK\tn\n")
	}
}
func fileHandle() int {
	index := integerArg(2, len(handles)-1)
	if index < 0 || !used[index] {
		return -1
	}
	return index
}
func openFile() {
	if fields != 4 || !stringArg(2, 127, false) {
		bad()
		return
	}
	ax := uint16(0x3d80) // Read, non-inheritable.
	if equalField(3, "swrite") {
		ax = 0x3d81
	} else if equalField(3, "screate") {
		ax = 0x3c00
	} else if !equalField(3, "sread") {
		bad()
		return
	}
	slot := 0
	for slot < len(used) && used[slot] {
		slot++
	}
	if slot == len(used) {
		send("ERR\tslimit\tsClose a file before opening another\n")
		return
	}
	dosCall(ax, 0, 0, argPointer(2))
	if failed(&regs) {
		return
	}
	handles[slot], used[slot] = regs.AX, true
	okInt(uint16(slot))
}
func readFile() {
	slot := fileHandle()
	count := integerArg(3, len(transfer))
	if fields != 4 || slot < 0 || count < 0 {
		bad()
		return
	}
	dosCall(0x3f00, handles[slot], uint16(count), pointer(&transfer[0]))
	if failed(&regs) {
		return
	}
	send("OK\ts")
	for i := 0; i < int(regs.AX); i++ {
		sendHex(transfer[i])
	}
	send("\n")
}
func writeFile() {
	slot := fileHandle()
	count := hexArg(3)
	if fields != 4 || slot < 0 || count < 0 {
		bad()
		return
	}
	// DOS zero-length writes truncate: do not silently truncate an empty chunk.
	if count == 0 {
		okInt(0)
		return
	}
	dosCall(0x4000, handles[slot], uint16(count), pointer(&transfer[0]))
	if !failed(&regs) {
		okInt(regs.AX)
	}
}
func findFile(first bool) {
	if first {
		if fields != 3 || !stringArg(2, 127, false) {
			bad()
			return
		}
	} else if fields != 2 {
		bad()
		return
	}
	if !first && !finding {
		send("OK\tn\n")
		return
	}
	dosCall(0x1a00, 0, 0, pointer(&dta[0]))
	regs.AX = 0x4f00
	if first {
		regs.AX = 0x4e00
		regs.CX = 0x37
		regs.DX = argPointer(2)
	}
	interrupt21(&regs)
	if regs.Flags&dos.FlagCarry != 0 {
		finding = false
		if regs.AX == 18 || regs.AX == 2 {
			send("OK\tn\n")
		} else {
			dosError(regs.AX)
		}
		return
	}
	finding = true
	// Raw OEM name bytes are hex, avoiding lossy or invalid UTF-8 on the wire.
	send("OK\tm2\tsname_hex\ts")
	for i := 30; i < 43 && dta[i] != 0; i++ {
		sendHex(dta[i])
	}
	send("\tsattributes\ti")
	sendInt(uint16(dta[21]))
	send("\n")
}
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
func dispatch() {
	if fields == 1 && equalField(0, "?") {
		send(manifest)
		return
	}
	if fields < 2 || !equalField(0, "CALL") {
		bad()
		return
	}
	if equalField(1, "ping") && fields == 2 {
		send("OK\tsDOS extension v1\n")
	} else if equalField(1, "open_file") {
		openFile()
	} else if equalField(1, "read_file") {
		readFile()
	} else if equalField(1, "write_file") {
		writeFile()
	} else if equalField(1, "close_file") {
		slot := fileHandle()
		if fields != 3 || slot < 0 {
			bad()
			return
		}
		dosCall(0x3e00, handles[slot], 0, 0)
		if !failed(&regs) {
			used[slot] = false
			send("OK\tn\n")
		}
	} else if equalField(1, "mkdir") {
		pathOperation(0x3900)
	} else if equalField(1, "rmdir") {
		pathOperation(0x3a00)
	} else if equalField(1, "remove") {
		pathOperation(0x4100)
	} else if equalField(1, "rename") {
		if fields != 4 || !stringArg(2, 127, false) || !stringArg(3, 127, false) {
			bad()
			return
		}
		regs.DI = argPointer(3)
		dosCall(0x5600, 0, 0, argPointer(2))
		if !failed(&regs) {
			send("OK\tn\n")
		}
	} else if equalField(1, "find_first") {
		findFile(true)
	} else if equalField(1, "find_next") {
		findFile(false)
	} else if equalField(1, "run") {
		runProgram()
	} else {
		bad()
	}
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

func sendHex(value byte) {
	hex := "0123456789abcdef"
	writeByte(hex[value>>4])
	writeByte(hex[value&15])
}
