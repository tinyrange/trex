//go:build renvo && win16 && display_agent

package main

import "unsafe"

// renvo:linkstatic GDI,Escape
func displayEscape(dc, escape, count, inputSegment, input, outputSegment, output uint16) uint16 {
	return 0
}

// renvo:linkstatic TREX,DisplayEntry
func displayEntry(record *uint16) uint16 { return 0 }

// renvo:linkstatic TREX,FarCall2
func displayCall(record *uint16) uint16 { return 0 }

// renvo:linkstatic KERNEL,Yield
func displayYield() {}

var resizeInitialized, resizeAvailable bool
var resizeEntry [8]uint16
var resizeRequest [5]uint16
var resizeReply [4]uint16
var resizeCompleted [2]uint16

func pollDisplayResize() {
	if !resizeInitialized {
		resizeInitialized = true
		resizeEntry[5], resizeEntry[6] = 0x5355, 0x5245 // USER\0
		resizeAvailable = displayEntry(&resizeEntry[0]) != 0
	}
	if !resizeAvailable {
		return
	}
	dc := getDC(0)
	if dc == 0 {
		return
	}
	// Real-mode Windows can compact the instance data between polls.
	segment = dataSegment()
	input := uint16(uintptr(unsafe.Pointer(&resizeRequest[0])))
	output := uint16(uintptr(unsafe.Pointer(&resizeReply[0])))
	resizeRequest[0] = 0
	if displayEscape(dc, 0x5452, 10, segment, input, segment, output) != 1 {
		releaseDC(0, dc)
		return
	}
	if resizeReply[0] == 0 && resizeReply[1] == 0 || resizeReply[0] == resizeCompleted[0] && resizeReply[1] == resizeCompleted[1] {
		releaseDC(0, dc)
		return
	}
	resizeRequest[0], resizeRequest[1], resizeRequest[2] = 1, resizeReply[0], resizeReply[1]
	result := uint16(1)
	if displayEscape(dc, 0x5452, 10, segment, input, segment, output) == 1 {
		resizeEntry[2], resizeEntry[3] = resizeReply[2], resizeReply[3]
		if displayCall(&resizeEntry[0]) != 0 && getSystemMetrics(0) == resizeReply[2] && getSystemMetrics(1) == resizeReply[3] && getDeviceCaps(dc, 8) == resizeReply[2] && getDeviceCaps(dc, 10) == resizeReply[3] {
			result = 0
		} else {
			result = 2
		}
	}
	resizeRequest[0], resizeRequest[3], resizeRequest[4] = 2, result, 0
	if displayEscape(dc, 0x5452, 10, segment, input, segment, output) == 1 {
		resizeCompleted[0], resizeCompleted[1] = resizeRequest[1], resizeRequest[2]
	}
	releaseDC(0, dc)
}
