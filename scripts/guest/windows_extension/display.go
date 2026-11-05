//go:build renvo && win16

package main

// USER's desktop geometry and GDI's device extent are separate observations.
// Comparing them with the captured frame distinguishes a real mode switch
// from a host-only framebuffer resize.
// renvo:linkstatic USER,GetSystemMetrics
func getSystemMetrics(index uint16) uint16 { return 0 }

// renvo:linkstatic USER,GetDC
func getDC(window uint16) uint16 { return 0 }

// renvo:linkstatic USER,ReleaseDC
func releaseDC(window, dc uint16) uint16 { return 0 }

// renvo:linkstatic GDI,GetDeviceCaps
func getDeviceCaps(dc, index uint16) uint16 { return 0 }

func displayGeometry() {
	dc := getDC(0)
	if dc == 0 {
		send("ERR\tsdisplay\tsCannot acquire desktop DC\n")
		return
	}
	width, height := getSystemMetrics(0), getSystemMetrics(1)
	deviceWidth, deviceHeight := getDeviceCaps(dc, 8), getDeviceCaps(dc, 10)
	releaseDC(0, dc)
	send("OK\tm4\tswidth\ti")
	sendInt(width)
	send("\tsheight\ti")
	sendInt(height)
	send("\tsdevice_width\ti")
	sendInt(deviceWidth)
	send("\tsdevice_height\ti")
	sendInt(deviceHeight)
	send("\n")
}
