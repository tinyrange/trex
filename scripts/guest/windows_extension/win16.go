//go:build renvo && win16

package main

import "unsafe"

// Register layout for the virtualized INT 21h directory services.
type platformRegisters struct {
	AX, BX, CX, DX uint16
	SI, DI         uint16
	Flags, ES      uint16
}

const pingReply = "OK\tsWindows Win16 extension v1\n"
const programOperation = "launch"

func dataSegment() uint16
func interrupt21(regs *platformRegisters)

// Native Pascal imports: a far pointer is passed as segment then offset.
// renvo:linkstatic USER,OpenComm
func openComm(seg, name, in, out uint16) uint16 { return 0 }

// renvo:linkstatic USER,BuildCommDCB
func buildCommDCB(seg, text, dseg, dcb uint16) uint16 { return 0 }

// renvo:linkstatic USER,SetCommState
func setCommState(seg, dcb uint16) uint16 { return 0 }

// renvo:linkstatic USER,ReadComm
func readComm(port, seg, buf, count uint16) uint16 { return 0 }

// renvo:linkstatic USER,WriteComm
func writeComm(port, seg, buf, count uint16) uint16 { return 0 }

// renvo:linkstatic USER,GetCommError
func getCommError(port, seg, status uint16) uint16 { return 0 }

// renvo:linkstatic USER,CloseComm
func closeComm(port uint16) uint16 { return 0 }

// renvo:linkstatic USER,PeekMessage
func peekMessage(seg, msg, window, first, last, remove uint16) uint16 { return 0 }

// renvo:linkstatic USER,TranslateMessage
func translateMessage(seg, msg uint16) uint16 { return 0 }

// renvo:linkstatic USER,DispatchMessage
func dispatchMessage(seg, msg uint16) uint16 { return 0 }

// renvo:linkstatic KERNEL,_lopen
func lopen(seg, path, mode uint16) uint16 { return 0 }

// renvo:linkstatic KERNEL,_lcreat
func lcreat(seg, path, attr uint16) uint16 { return 0 }

// renvo:linkstatic KERNEL,_lclose
func lclose(handle uint16) uint16 { return 0 }

// renvo:linkstatic KERNEL,_lread
func lread(handle, seg, buf, count uint16) uint16 { return 0 }

// renvo:linkstatic KERNEL,_lwrite
func lwrite(handle, seg, buf, count uint16) uint16 { return 0 }

// renvo:linkstatic KERNEL,LoadModule
func loadModule(seg, path, pseg, params uint16) uint16 { return 0 }

var portName = [5]byte{'C', 'O', 'M', '1', 0}
var settings = [16]byte{'C', 'O', 'M', '1', ':', '9', '6', '0', '0', ',', 'n', ',', '8', ',', '1', 0}
var dcb [64]byte
var message [18]byte
var serialByte [1]byte
var segment uint16
var port uint16
var stopped bool

// Yield through USER; do not poll the UART or use DOS PSP/EXEC startup.
func pump() {
	p := pointer(&message[0])
	if peekMessage(segment, p, 0, 0, 0, 1) != 0 {
		if message[2] == 0x12 && message[3] == 0 { // WM_QUIT
			stopped = true
			return
		}
		translateMessage(segment, p)
		dispatchMessage(segment, p)
	}
}
func writeByte(value byte) {
	serialByte[0] = value
	for !stopped {
		n := writeComm(port, segment, pointer(&serialByte[0]), 1)
		if n == 1 {
			return
		}
		// Negative counts may mean partial writes: abort, never replay bytes.
		if n != 0 {
			getCommError(port, 0, 0)
			stopped = true
			return
		}
		pump()
	}
}

// Native KERNEL file operations report -1, not DOS extended errors.
func fileCall(ax, bx, cx, dx uint16) {
	result := uint16(0xffff)
	if ax == 0x3c00 {
		result = lcreat(segment, dx, 0)
	} else if ax == 0x3d80 || ax == 0x3d81 {
		result = lopen(segment, dx, ax&1)
	} else if ax == 0x3e00 {
		result = lclose(bx)
	} else if ax == 0x3f00 {
		result = lread(bx, segment, dx, cx)
	} else if ax == 0x4000 {
		result = lwrite(bx, segment, dx, cx)
	}
	regs.Flags = 0
	regs.AX = result
	if result == 0xffff {
		regs.Flags = 1
	}
}

var tail [128]byte
var launchParams [7]uint16
var show = [2]uint16{2, 1}

func runProgram() {
	if fields != 4 || !stringArg(2, 127, false) || !stringArg(3, 126, true) {
		bad()
		return
	}
	n := ends[3] - starts[3] - 1
	tail[0] = byte(n)
	for i := 0; i < n; i++ {
		tail[i+1] = input[starts[3]+1+i]
	}
	tail[n+1] = 13
	launchParams[0] = 0 // Inherit environment.
	launchParams[1] = pointer(&tail[0])
	launchParams[2] = segment
	launchParams[3] = uint16(uintptr(unsafe.Pointer(&show[0])))
	launchParams[4] = segment
	launchParams[5] = 0
	launchParams[6] = 0
	result := loadModule(segment, argPointer(2), segment, uint16(uintptr(unsafe.Pointer(&launchParams[0]))))
	finding = false
	if result < 32 {
		send("ERR\tslaunch\tsLoadModule error ")
		sendInt(result)
		send("\n")
		return
	}
	// Instance handles are not exit codes or waitable process handles.
	send("OK\tm1\tsinstance\ti")
	sendInt(result)
	send("\n")
}
func main() {
	segment = dataSegment()
	port = openComm(segment, pointer(&portName[0]), 2048, 2048)
	if port&0x8000 != 0 {
		return
	}
	if buildCommDCB(segment, pointer(&settings[0]), segment, pointer(&dcb[0])) != 0 {
		stopped = true
	}
	dcb[0] = byte(port)
	if !stopped && setCommState(segment, pointer(&dcb[0])) != 0 {
		stopped = true
	}
	// The service consumes this startup record before exposing discovery.
	// Requests sent before OpenComm would otherwise be lost during boot.
	send("WINEXT_READY\n")
	n := 0
	overflow := false
	for !stopped {
		pump()
		got := readComm(port, segment, pointer(&serialByte[0]), 1)
		if got == 0 {
			continue
		}
		if got != 1 {
			code := getCommError(port, 0, 0)
			send("ERR\tstransport\tsSerial receive error ")
			sendInt(code)
			send("\n")
			stopped = true
			break
		}
		c := serialByte[0]
		if c == 10 {
			if overflow || !parse(n) {
				bad()
			} else {
				dispatch()
			}
			n = 0
			overflow = false
		} else if n < lineLimit {
			input[n] = c
			n++
		} else {
			overflow = true
		}
	}
	for i := 0; i < len(used); i++ {
		if used[i] {
			lclose(handles[i])
		}
	}
	closeComm(port)
}
