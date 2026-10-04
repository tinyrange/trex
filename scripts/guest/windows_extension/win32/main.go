//go:build renvo && windows

package main

import "unsafe"

// All OS calls use the target's native Windows ABI, not a DOS compatibility task.
// renvo:linkstatic kernel32.dll,CreateFileA
func createFile(path uintptr, access, share uint32, security uintptr, disposition, flags uint32, template uintptr) uintptr {
	return 0
}

// renvo:linkstatic kernel32.dll,CloseHandle
func closeHandle(handle uintptr) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,ReadFile
func readFile(handle, buffer uintptr, count uint32, done, overlapped uintptr) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,WriteFile
func writeFile(handle, buffer uintptr, count uint32, done, overlapped uintptr) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,GetLastError
func getLastError() uint32 { return 0 }

// renvo:linkstatic kernel32.dll,Sleep
func sleepMilliseconds(milliseconds uint32) {}

// renvo:linkstatic kernel32.dll,GetCommState
func getCommState(handle, dcb uintptr) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,SetCommState
func setCommState(handle, dcb uintptr) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,SetCommTimeouts
func setCommTimeouts(handle, timeouts uintptr) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,CreateDirectoryA
func createDirectory(path, security uintptr) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,RemoveDirectoryA
func removeDirectory(path uintptr) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,DeleteFileA
func deleteFile(path uintptr) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,MoveFileA
func moveFile(old, new uintptr) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,FindFirstFileA
func findFirstFile(pattern, data uintptr) uintptr { return 0 }

// renvo:linkstatic kernel32.dll,FindNextFileA
func findNextFile(handle, data uintptr) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,FindClose
func findClose(handle uintptr) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,CreateProcessA
func createProcess(app, command, processSecurity, threadSecurity uintptr, inherit, flags uint32, environment, cwd, startup, info uintptr) uint32 {
	return 0
}

// renvo:linkstatic kernel32.dll,WaitForSingleObject
func waitForSingleObject(handle uintptr, milliseconds uint32) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,GetExitCodeProcess
func getExitCodeProcess(handle, code uintptr) uint32 { return 0 }

// renvo:linkstatic user32.dll,WaitForInputIdle
func waitForInputIdle(handle uintptr, milliseconds uint32) uint32 { return 0 }

// renvo:linkstatic kernel32.dll,TerminateProcess
func terminateProcess(handle uintptr, code uint32) uint32 { return 0 }

type startupInfo struct {
	Size                                            uint32
	Reserved, Desktop, Title                        uintptr
	X, Y, XSize, YSize, XCount, YCount, Fill, Flags uint32
	Show, ReservedBytes                             uint16
	ReservedPointer, Input, Output, Error           uintptr
}
type processInfo struct {
	Process, Thread     uintptr
	ProcessID, ThreadID uint32
}
type commState struct {
	Length, Baud, Flags           uint32
	Reserved, XonLimit, XoffLimit uint16
	ByteSize, Parity, StopBits    byte
	Xon, Xoff, Error, Eof, Event  byte
	Reserved1                     uint16
}

var serial uintptr
var serialByte [1]byte
var serialDone uint32
var transportFailed bool
var fileHandles [8]uintptr
var fileUsed [8]bool
var processHandles [8]uintptr
var processUsed [8]bool
var search uintptr
var searching bool
var findData [320]byte
var digits [10]byte
var done uint32
var dcb commState
var timeouts [5]uint32
var startup startupInfo
var process processInfo
var exitCode uint32
var commandLine [600]byte
var portName = [5]byte{'C', 'O', 'M', '1', 0}

func ptr(value *byte) uintptr     { return uintptr(unsafe.Pointer(value)) }
func arg(index int) uintptr       { return ptr(&input[starts[index]+1]) }
func invalid(handle uintptr) bool { return handle == ^uintptr(0) }
func writeByte(value byte) {
	if transportFailed {
		return
	}
	serialByte[0] = value
	serialDone = 0
	if writeFile(serial, ptr(&serialByte[0]), 1, uintptr(unsafe.Pointer(&serialDone)), 0) == 0 || serialDone != 1 {
		transportFailed = true // An uncertain write is never replayed.
	}
}
func send(value string) {
	for i := 0; i < len(value); i++ {
		writeByte(value[i])
	}
}
func number(value uint32) {
	at := len(digits)
	for {
		at--
		digits[at] = byte(value%10) + '0'
		value /= 10
		if value == 0 {
			break
		}
	}
	for at < len(digits) {
		writeByte(digits[at])
		at++
	}
}
func okNumber(value uint32) { send("OK\ti"); number(value); send("\n") }
func bad()                  { send("ERR\tsbad_call\tsInvalid arguments or unsupported call\n") }
func osError(code uint32)   { send("ERR\tswin32\tsWindows error "); number(code); send("\n") }
func booleanResult(ok uint32) {
	if ok == 0 {
		osError(getLastError())
	} else {
		send("OK\tn\n")
	}
}
func handleArg(used []bool) int {
	slot := integerArg(2, len(used)-1)
	if slot < 0 || !used[slot] {
		return -1
	}
	return slot
}
func sendHex(data []byte) {
	hex := "0123456789abcdef"
	for i := 0; i < len(data); i++ {
		writeByte(hex[data[i]>>4])
		writeByte(hex[data[i]&15])
	}
}
func openFile() {
	if fields != 4 || !stringArg(2, 259, false) {
		bad()
		return
	}
	access := uint32(0x80000000)
	disposition := uint32(3)
	if equalField(3, "swrite") {
		access = 0x40000000
	} else if equalField(3, "screate") {
		access = 0x40000000
		disposition = 2
	} else if !equalField(3, "sread") {
		bad()
		return
	}
	slot := -1
	for i := 0; i < len(fileUsed); i++ {
		if !fileUsed[i] {
			slot = i
			break
		}
	}
	if slot < 0 {
		send("ERR\tsbusy\tsNo free file slots\n")
		return
	}
	handle := createFile(arg(2), access, 3, 0, disposition, 0x80, 0)
	if invalid(handle) {
		osError(getLastError())
		return
	}
	fileUsed[slot] = true
	fileHandles[slot] = handle
	okNumber(uint32(slot))
}
func transferFile(writing bool) {
	if fields != 4 {
		bad()
		return
	}
	slot := handleArg(fileUsed[:])
	if slot < 0 {
		bad()
		return
	}
	count := 0
	if writing {
		count = hexArg(3)
	} else {
		count = integerArg(3, len(transfer))
	}
	if count < 0 {
		bad()
		return
	}
	done = 0
	ok := uint32(1)
	if count > 0 {
		if writing {
			ok = writeFile(fileHandles[slot], ptr(&transfer[0]), uint32(count), uintptr(unsafe.Pointer(&done)), 0)
		} else {
			ok = readFile(fileHandles[slot], ptr(&transfer[0]), uint32(count), uintptr(unsafe.Pointer(&done)), 0)
		}
	}
	if ok == 0 {
		osError(getLastError())
		return
	}
	if done > uint32(count) {
		send("ERR\tsio\tsInvalid transfer count\n")
		return
	}
	if writing {
		okNumber(done)
	} else {
		send("OK\ts")
		sendHex(transfer[:int(done)])
		send("\n")
	}
}
func directoryEntry() {
	size := 0
	for size < 260 && findData[44+size] != 0 {
		size++
	}
	attributes := uint32(findData[0]) | uint32(findData[1])<<8 | uint32(findData[2])<<16 | uint32(findData[3])<<24
	send("OK\tm2\tsname_hex\ts")
	sendHex(findData[44 : 44+size])
	send("\tsattributes\ti")
	number(attributes)
	send("\n")
}
func find(first bool) {
	if first {
		if fields != 3 || !stringArg(2, 259, false) {
			bad()
			return
		}
		if searching {
			findClose(search)
			searching = false
		}
		search = findFirstFile(arg(2), ptr(&findData[0]))
		if invalid(search) {
			code := getLastError()
			if code == 2 || code == 18 {
				send("OK\tn\n")
			} else {
				osError(code)
			}
			return
		}
		searching = true
	} else {
		if fields != 2 {
			bad()
			return
		}
		if !searching {
			send("OK\tn\n")
			return
		}
		if findNextFile(search, ptr(&findData[0])) == 0 {
			code := getLastError()
			findClose(search)
			searching = false
			if code == 18 {
				send("OK\tn\n")
			} else {
				osError(code)
			}
			return
		}
	}
	directoryEntry()
}
func launch() {
	if fields != 5 || !stringArg(2, 259, false) || !stringArg(3, 259, true) || !stringArg(4, 259, true) {
		bad()
		return
	}
	// lpApplicationName is explicit; quote only argv[0], preserve the caller's
	// literal argument tail. A quote cannot be part of a Windows executable path.
	for i := starts[2] + 1; i < ends[2]; i++ {
		if input[i] == '"' {
			bad()
			return
		}
	}
	slot := -1
	for i := 0; i < len(processUsed); i++ {
		if !processUsed[i] {
			slot = i
			break
		}
	}
	if slot < 0 {
		send("ERR\tsbusy\tsNo free process slots\n")
		return
	}
	n := 0
	commandLine[n] = '"'
	n++
	for i := starts[2] + 1; i < ends[2]; i++ {
		commandLine[n] = input[i]
		n++
	}
	commandLine[n] = '"'
	n++
	if ends[3]-starts[3] > 1 {
		commandLine[n] = ' '
		n++
	}
	for i := starts[3] + 1; i < ends[3]; i++ {
		commandLine[n] = input[i]
		n++
	}
	commandLine[n] = 0
	cwd := uintptr(0)
	if ends[4]-starts[4] > 1 {
		cwd = arg(4)
	}
	startup = startupInfo{}
	startup.Size = uint32(unsafe.Sizeof(startup))
	process = processInfo{}
	if createProcess(arg(2), ptr(&commandLine[0]), 0, 0, 0, 0, 0, cwd, uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&process))) == 0 {
		osError(getLastError())
		return
	}
	closeHandle(process.Thread)
	processHandles[slot] = process.Process
	processUsed[slot] = true
	send("OK\tm2\tsprocess\ti")
	number(uint32(slot))
	send("\tspid\ti")
	number(process.ProcessID)
	send("\n")
}
func poll() {
	if fields != 3 {
		bad()
		return
	}
	slot := handleArg(processUsed[:])
	if slot < 0 {
		bad()
		return
	}
	result := waitForSingleObject(processHandles[slot], 0)
	if result == 258 {
		send("OK\tm1\tsrunning\tb1\n")
		return
	}
	if result != 0 {
		osError(getLastError())
		return
	}
	if getExitCodeProcess(processHandles[slot], uintptr(unsafe.Pointer(&exitCode))) == 0 {
		osError(getLastError())
		return
	}
	send("OK\tm2\tsrunning\tb0\tsexit_code\ti")
	number(exitCode)
	send("\n")
}
func closeSlot(processSlot bool) {
	if fields != 3 {
		bad()
		return
	}
	slot := -1
	handle := uintptr(0)
	if processSlot {
		slot = handleArg(processUsed[:])
		if slot >= 0 {
			handle = processHandles[slot]
		}
	} else {
		slot = handleArg(fileUsed[:])
		if slot >= 0 {
			handle = fileHandles[slot]
		}
	}
	if slot < 0 {
		bad()
		return
	}
	if closeHandle(handle) == 0 {
		osError(getLastError())
		return
	}
	if processSlot {
		processUsed[slot] = false
	} else {
		fileUsed[slot] = false
	}
	send("OK\tn\n")
}
func inputIdle() {
	if fields != 4 {
		bad()
		return
	}
	slot := handleArg(processUsed[:])
	milliseconds := integerArg(3, 1000)
	if slot < 0 || milliseconds < 0 {
		bad()
		return
	}
	result := waitForInputIdle(processHandles[slot], uint32(milliseconds))
	if result == 0 {
		send("OK\tb1\n")
	} else if result == 258 {
		send("OK\tb0\n")
	} else {
		osError(getLastError())
	}
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
		send("OK\tsWindows Win32 extension v1\n")
	} else if equalField(1, "open_file") {
		openFile()
	} else if equalField(1, "read_file") {
		transferFile(false)
	} else if equalField(1, "write_file") {
		transferFile(true)
	} else if equalField(1, "close_file") {
		closeSlot(false)
	} else if equalField(1, "find_first") {
		find(true)
	} else if equalField(1, "find_next") {
		find(false)
	} else if equalField(1, "start_process") {
		launch()
	} else if equalField(1, "wait_input_idle") {
		inputIdle()
	} else if equalField(1, "poll_process") {
		poll()
	} else if equalField(1, "close_process") {
		closeSlot(true)
	} else if equalField(1, "terminate_process") {
		if fields != 4 {
			bad()
			return
		}
		slot := handleArg(processUsed[:])
		code := integerArg(3, 2147483647)
		if slot < 0 || code < 0 {
			bad()
			return
		}
		booleanResult(terminateProcess(processHandles[slot], uint32(code)))
	} else if equalField(1, "rename") {
		if fields != 4 || !stringArg(2, 259, false) || !stringArg(3, 259, false) {
			bad()
			return
		}
		booleanResult(moveFile(arg(2), arg(3)))
	} else if equalField(1, "mkdir") || equalField(1, "rmdir") || equalField(1, "remove") {
		if fields != 3 || !stringArg(2, 259, false) {
			bad()
			return
		}
		if equalField(1, "mkdir") {
			booleanResult(createDirectory(arg(2), 0))
		} else if equalField(1, "rmdir") {
			booleanResult(removeDirectory(arg(2)))
		} else {
			booleanResult(deleteFile(arg(2)))
		}
	} else {
		bad()
	}
}
func openSerial() uintptr {
	// NT 3.5 starts Serial as an automatic service. Winlogon's Userinit can
	// run before COM1 exists (observed ERROR_FILE_NOT_FOUND). Retry only that
	// definite no-handle result; sharing/access errors and uncertain writes
	// are never retried. Startup is bounded to thirty seconds.
	for attempt := 0; attempt < 301; attempt++ {
		handle := createFile(ptr(&portName[0]), 0xc0000000, 0, 0, 3, 0, 0)
		if !invalid(handle) || getLastError() != 2 || attempt == 300 {
			return handle
		}
		sleepMilliseconds(100)
	}
	return ^uintptr(0)
}
func main() {
	serial = openSerial()
	if invalid(serial) {
		return
	}
	dcb.Length = uint32(unsafe.Sizeof(dcb))
	if getCommState(serial, uintptr(unsafe.Pointer(&dcb))) == 0 {
		closeHandle(serial)
		return
	}
	// Bound an idle read. A successful zero-byte completion is a timeout,
	// not EOF on a serial device. Win9x VCOMM must be allowed to complete
	// these reads rather than keeping an unbounded request outstanding.
	timeouts[2] = 1000
	dcb.Baud = 9600
	dcb.Flags = 0x1011
	dcb.ByteSize = 8
	dcb.Parity = 0
	dcb.StopBits = 0
	if setCommState(serial, uintptr(unsafe.Pointer(&dcb))) == 0 || setCommTimeouts(serial, uintptr(unsafe.Pointer(&timeouts[0]))) == 0 {
		closeHandle(serial)
		return
	}
	send("WINEXT_READY\n")
	n := 0
	overflow := false
	for !transportFailed {
		serialDone = 0
		if readFile(serial, ptr(&serialByte[0]), 1, uintptr(unsafe.Pointer(&serialDone)), 0) == 0 {
			break
		}
		if serialDone == 0 {
			continue // No byte was consumed; preserve any partial input line.
		}
		if serialDone != 1 {
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
	for i := 0; i < len(fileUsed); i++ {
		if fileUsed[i] {
			closeHandle(fileHandles[i])
		}
	}
	for i := 0; i < len(processUsed); i++ {
		if processUsed[i] {
			closeHandle(processHandles[i])
		}
	}
	if searching {
		findClose(search)
	}
	closeHandle(serial)
}
