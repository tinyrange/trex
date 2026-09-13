//go:build renvo_nt31

package main

import "unsafe"

// NT 3.1 DDK VIDEO_HW_INITIALIZATION_DATA, VIDEO_REQUEST_PACKET and VideoPort
// interfaces. The physical aperture is the TinyRangeX TRF1 RAM display ABI.
const fbPhysical = 0xe0000000
const fbSize = 8 << 20
const fbMagic = 0x31465254

// renvo:linkstatic videoprt.sys,VideoPortInitialize
func videoInitialize(driver, path, initialization, context uintptr) uint32 { return 0 }

// renvo:linkstatic videoprt.sys,VideoPortGetDeviceBase
func deviceBase(extension, low, high, length, ioSpace uintptr) uintptr { return 0 }

// renvo:linkstatic videoprt.sys,VideoPortVerifyAccessRanges
func verifyRanges(extension, count, ranges uintptr) uint32 { return 0 }

// renvo:linkstatic videoprt.sys,VideoPortMapMemory
func mapMemory(extension, low, high, length, ioSpace, address uintptr) uint32 { return 0 }

// renvo:linkstatic videoprt.sys,VideoPortUnmapMemory
func unmapMemory(extension, address, process uintptr) uint32 { return 0 }

func get(p uintptr) uint32      { return *(*uint32)(unsafe.Pointer(p)) }
func put(p uintptr, v uint32)   { *(*uint32)(unsafe.Pointer(p)) = v }
func address(p *uint32) uintptr { return uintptr(unsafe.Pointer(p)) }

//export DriverEntry
func DriverEntry(driver, path uintptr) uint32 {
	var init [8]uintptr
	find, initialize, start := findAdapter, initializeAdapter, startIO
	init[0] = 32
	init[1] = 1 // ISA, no PCI configuration-space dependency
	init[2] = *(*uintptr)(unsafe.Pointer(&find))
	init[3] = *(*uintptr)(unsafe.Pointer(&initialize))
	init[5] = *(*uintptr)(unsafe.Pointer(&start))
	init[6] = 4
	return videoInitialize(driver, path, uintptr(unsafe.Pointer(&init)), 0)
}

func findAdapter(extension, context, arguments, config, again uintptr) uint32 {
	*(*byte)(unsafe.Pointer(again)) = 0
	var ranges [4]uint32
	ranges[0] = fbPhysical
	ranges[2] = fbSize
	ranges[3] = 0x100 // memory, visible, not shared
	status := verifyRanges(extension, 1, uintptr(unsafe.Pointer(&ranges)))
	if status != 0 {
		return status
	}
	base := deviceBase(extension, fbPhysical, 0, fbSize, 0)
	if base == 0 {
		return 8
	}
	if get(base) != fbMagic {
		return 55
	}
	put(extension, uint32(base))
	return 0
}
func initializeAdapter(extension uintptr) uint32 { return 1 }

func modeInfo(output uintptr) {
	values := [19]uint32{76, 0, 1024, 768, 4096, 1, 32, 60, 270, 203, 8, 8, 8, 0xff0000, 0xff00, 0xff, 0x23, 1024, 768}
	for i := 0; i < 19; i++ {
		put(output+uintptr(i*4), values[i])
	}
}

func startIO(extension, request uintptr) uint32 {
	code := get(request)
	status := uintptr(get(request + 4))
	input := uintptr(get(request + 8))
	inputLength := get(request + 12)
	output := uintptr(get(request + 16))
	outputLength := get(request + 20)
	put(status, 0)
	put(status+4, 0)
	switch code {
	case 0x230400, 0x230408: // query available/current modes
		if outputLength < 76 {
			put(status, 122)
		} else {
			modeInfo(output)
			put(status+4, 76)
		}
	case 0x230404:
		if outputLength < 8 {
			put(status, 122)
		} else {
			put(output, 1)
			put(output+4, 76)
			put(status+4, 8)
		}
	case 0x23040c: // select mode; pixels are mapped separately into CSRSS
		if inputLength < 4 {
			put(status, 122)
		} else if get(input)&0x7fffffff != 0 {
			put(status, 87)
		} else {
			base := uintptr(get(extension))
			put(base+8, 1024)
			put(base+12, 768)
			put(base+16, 4096)
			put(base+20, 1)
			put(base+4, 1)
		}
	case 0x230410:
		put(uintptr(get(extension))+4, 0)
	case 0x230458:
		if inputLength < 4 || outputLength < 16 {
			put(status, 122)
		} else {
			length := uint32(fbSize)
			space := uint32(0)
			mapped := get(input)
			result := mapMemory(extension, fbPhysical, 0, address(&length), address(&space), address(&mapped))
			put(status, result)
			if result == 0 {
				put(output, mapped)
				put(output+4, length)
				put(output+8, mapped+4096)
				put(output+12, 1024*768*4)
				put(status+4, 16)
			}
		}
	case 0x23045c:
		if inputLength < 4 {
			put(status, 122)
		} else {
			put(status, unmapMemory(extension, uintptr(get(input)), 0))
		}
	default:
		put(status, 1)
	}
	return 1
}
