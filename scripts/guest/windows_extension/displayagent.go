//go:build renvo && win16 && display_agent

package main

// This endpoint leaves room for display work within a Win16 near-code segment.
// The independent file endpoint retains its existing complete capability set.
const manifest = "API\t1\t1024\nABOUT\tsNative Win16 display inspection and application launch\nFN\tping\tstr\tsReadiness\nEND\nFN\tdisplay_geometry\tmap\tsUSER desktop size and GDI device extent in pixels\nEND\nFN\twindow_active\tmap\tsActive window bounds, instance, and raw ANSI caption hex\nEND\nFN\twindow_maximize\tmap\tsMaximize the active window through USER\nEND\nFN\tlaunch\tmap\tsLoad native Windows EXE; returns instance, not exit status\nARG\tpath\tstr\ts\nARG\ttail\tstr\ts\nEND\nDONE\n"

func dispatchCall() {
	if fields == 1 && equalField(0, "?") {
		send(manifest)
		return
	}
	if fields < 2 || !equalField(0, "CALL") {
		bad()
		return
	}
	if fields == 2 && equalField(1, "ping") {
		send(pingReply)
	} else if fields == 2 && equalField(1, "display_geometry") {
		displayGeometry()
	} else if fields == 2 && equalField(1, "window_active") {
		activeWindow()
	} else if fields == 2 && equalField(1, "window_maximize") {
		showDisplayWindow(getActiveWindow(), 3)
		activeWindow()
	} else if equalField(1, "launch") {
		runProgram()
	} else {
		bad()
	}
}

// renvo:linkstatic USER,GetActiveWindow
func getActiveWindow() uint16 { return 0 }

// renvo:linkstatic USER,GetWindowWord
func getWindowWord(window, index uint16) uint16 { return 0 }

// renvo:linkstatic USER,GetWindowRect
func getWindowRect(window, segment, rect uint16) uint16 { return 0 }

// renvo:linkstatic USER,GetWindowText
func getWindowText(window, segment, text, count uint16) uint16 { return 0 }

// renvo:linkstatic USER,ShowWindow
func showDisplayWindow(window, command uint16) uint16 { return 0 }

var displayWindowRect [8]byte
var displayWindowTitle [128]byte

func sendCoordinate(low, high byte) {
	value := uint16(low) | uint16(high)<<8
	if value&0x8000 != 0 {
		send("-")
		value = 0 - value
	}
	sendInt(value)
}

func activeWindow() {
	window := getActiveWindow()
	getWindowRect(window, segment, pointer(&displayWindowRect[0]))
	count := getWindowText(window, segment, pointer(&displayWindowTitle[0]), 128)
	if count > 127 {
		count = 127
	}
	send("OK\tm7\tshandle\ti")
	sendInt(window)
	send("\tsinstance\ti")
	sendInt(getWindowWord(window, 0xfffa))
	send("\tsleft\ti")
	sendCoordinate(displayWindowRect[0], displayWindowRect[1])
	send("\tstop\ti")
	sendCoordinate(displayWindowRect[2], displayWindowRect[3])
	send("\tsright\ti")
	sendCoordinate(displayWindowRect[4], displayWindowRect[5])
	send("\tsbottom\ti")
	sendCoordinate(displayWindowRect[6], displayWindowRect[7])
	send("\tstitle_hex\ts")
	for i := uint16(0); i < count; i++ {
		sendHex(displayWindowTitle[i])
	}
	send("\n")
}
