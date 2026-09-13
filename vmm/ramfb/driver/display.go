//go:build renvo_nt31

package main

import "unsafe"

// This is the NT 3.1 user-mode display DDI, hosted by CSRSS/WINSRV, not WDDM.
// GDI owns rendering: an unhooked 32-bpp engine bitmap points at mapped RAM.
// renvo:linkstatic kernel32.dll,LocalAlloc
func alloc(flags, size uintptr) uintptr { return 0 }

// renvo:linkstatic kernel32.dll,LocalFree
func free(p uintptr) uintptr { return 0 }

// renvo:linkstatic kernel32.dll,DeviceIoControl
func ioctl(driver, code, input, inputSize, output, outputSize, returned, overlapped uintptr) uint32 {
	return 0
}

// renvo:linkstatic winsrv.dll,EngCreateBitmap
func createBitmap(width, height, stride, format, flags, pixels uintptr) uintptr { return 0 }

// renvo:linkstatic winsrv.dll,EngAssociateSurface
func associateSurface(surface, device, hooks uintptr) uint32 { return 0 }

// renvo:linkstatic winsrv.dll,EngDeleteSurface
func deleteSurface(surface uintptr) uint32 { return 0 }

// renvo:linkstatic winsrv.dll,EngCreatePalette
func createPalette(mode, count, colors, red, green, blue uintptr) uintptr { return 0 }

// renvo:linkstatic winsrv.dll,EngDeletePalette
func deletePalette(palette uintptr) uint32 { return 0 }

func get(p uintptr) uint32    { return *(*uint32)(unsafe.Pointer(p)) }
func put(p uintptr, v uint32) { *(*uint32)(unsafe.Pointer(p)) = v }
func ptr(p *uint32) uintptr   { return uintptr(unsafe.Pointer(p)) }
func zero(p, n uintptr) {
	for i := uintptr(0); i < n; i++ {
		*(*byte)(unsafe.Pointer(p + i)) = 0
	}
}
func copyBytes(dst, src, n uintptr) {
	for i := uintptr(0); i < n; i++ {
		*(*byte)(unsafe.Pointer(dst + i)) = *(*byte)(unsafe.Pointer(src + i))
	}
}
func wide(dst uintptr, s string) {
	for i := 0; i < len(s); i++ {
		*(*uint16)(unsafe.Pointer(dst + uintptr(i*2))) = uint16(s[i])
	}
}

var functions [22]uintptr

//export DrvDisableDriver
func DrvDisableDriver() {}

//export DrvEnableDriver
func DrvEnableDriver(version, size, output uintptr) uint32 {
	if size < 12 {
		return 0
	}
	a, b, c, d, e, f, g, h, i := enablePDEV, completePDEV, disablePDEV, enableSurface, disableSurface, assertMode, setPointerShape, movePointer, getModes
	functions[0] = 0
	functions[1] = *(*uintptr)(unsafe.Pointer(&a))
	functions[2] = 1
	functions[3] = *(*uintptr)(unsafe.Pointer(&b))
	functions[4] = 2
	functions[5] = *(*uintptr)(unsafe.Pointer(&c))
	functions[6] = 3
	functions[7] = *(*uintptr)(unsafe.Pointer(&d))
	functions[8] = 4
	functions[9] = *(*uintptr)(unsafe.Pointer(&e))
	functions[10] = 5
	functions[11] = *(*uintptr)(unsafe.Pointer(&f))
	functions[12] = 29
	functions[13] = *(*uintptr)(unsafe.Pointer(&g))
	functions[14] = 30
	functions[15] = *(*uintptr)(unsafe.Pointer(&h))
	functions[16] = 41
	functions[17] = *(*uintptr)(unsafe.Pointer(&i))
	j, k := ditherColor, setPalette
	functions[18] = 13
	functions[19] = *(*uintptr)(unsafe.Pointer(&j))
	functions[20] = 22
	functions[21] = *(*uintptr)(unsafe.Pointer(&k))
	put(output, 0x10000)
	put(output+4, 11)
	put(output+8, uint32(uintptr(unsafe.Pointer(&functions))))
	return 1
}

// PDEV words: driver, engine device, surface, mapping base, pixels, palette,
// followed by six standard hatch bitmaps. All storage is per PDEV.
func enablePDEV(mode, logical, count, patterns, gdiSize, gdi, devSize, dev, dataFile, name, driver uintptr) uintptr {
	if gdiSize < 248 || devSize < 296 {
		return 0
	}
	p := alloc(0x40, 48)
	if p == 0 {
		return 0
	}
	put(p, uint32(driver))
	palette := createPalette(2, 0, 0, 0xff0000, 0xff00, 0xff)
	if palette == 0 {
		free(p)
		return 0
	}
	put(p+20, uint32(palette))
	zero(gdi, 248)
	zero(dev, 296)
	info := [27]uint32{0x1000, 1, 270, 203, 1024, 768, 32, 1, 2048, 0, 96, 96, 0x2000, 8, 8, 8, 36, 36, 51, 1, 1, 3, 0, 0, 0, 0, 0}
	for i := 0; i < 27; i++ {
		put(gdi+uintptr(i*4), info[i])
	}
	// COLORINFO: RGB primaries, alignment white, gamma 2.0; no dye correction.
	put(gdi+108, 6700)
	put(gdi+112, 3300)
	put(gdi+120, 2100)
	put(gdi+124, 7100)
	put(gdi+132, 1400)
	put(gdi+136, 800)
	put(gdi+180, 3127)
	put(gdi+184, 3290)
	put(gdi+192, 20000)
	put(gdi+196, 20000)
	put(gdi+200, 20000)
	put(gdi+232, 4)
	put(gdi+236, 3)
	put(gdi+240, 7)
	put(gdi+244, 4)
	put(dev, 0x500)
	font(dev+4, 16, 7, 700, "System", 2)
	font(dev+96, 12, 9, 400, "MS Sans Serif", 2)
	font(dev+188, 12, 9, 400, "Courier", 1)
	put(dev+284, 6)
	put(dev+288, 0x00080008)
	put(dev+292, uint32(palette))
	for i := uintptr(0); i < count && i < 6; i++ {
		var bits [32]byte
		for y := 0; y < 8; y++ {
			value := byte(0)
			for x := 0; x < 8; x++ {
				on := false
				switch i {
				case 0:
					on = y == 3
				case 1:
					on = x == 3
				case 2:
					on = x+y == 7
				case 3:
					on = x == y
				case 4:
					on = x == 3 || y == 3
				case 5:
					on = x == y || x+y == 7
				}
				if on {
					value |= 0x80 >> uint(x)
				}
			}
			bits[y*4] = value
		}
		// Let GDI own pattern storage, then fill the bitmap via lock.
		bitmap := createPattern(uintptr(unsafe.Pointer(&bits)))
		if bitmap == 0 {
			disablePDEV(p)
			return 0
		}
		put(p+24+i*4, uint32(bitmap))
		put(patterns+i*4, uint32(bitmap))
	}
	return p
}

// renvo:linkstatic winsrv.dll,EngLockSurface
func lockSurface(surface uintptr) uintptr { return 0 }

// renvo:linkstatic winsrv.dll,EngUnlockSurface
func unlockSurface(surface uintptr) {}
func createPattern(bits uintptr) uintptr {
	b := createBitmap(8, 8, 4, 1, 1, 0)
	if b == 0 {
		return 0
	}
	s := lockSurface(b)
	if s == 0 {
		deleteSurface(b)
		return 0
	}
	copyBytes(uintptr(get(s+32)), bits, 32)
	unlockSurface(s)
	return b
}
func font(p uintptr, height, width, weight uint32, name string, pitch byte) {
	put(p, height)
	put(p+4, width)
	put(p+16, weight)
	*(*byte)(unsafe.Pointer(p + 27)) = pitch
	wide(p+28, name)
}
func completePDEV(p, device uintptr) { put(p+4, uint32(device)) }
func disablePDEV(p uintptr) {
	if p == 0 {
		return
	}
	for i := uintptr(0); i < 6; i++ {
		b := get(p + 24 + i*4)
		if b != 0 {
			deleteSurface(uintptr(b))
		}
	}
	if get(p+20) != 0 {
		deletePalette(uintptr(get(p + 20)))
	}
	free(p)
}
func enableSurface(p uintptr) uintptr {
	var returned, mode uint32
	if ioctl(uintptr(get(p)), 0x23040c, ptr(&mode), 4, 0, 0, ptr(&returned), 0) == 0 {
		return 0
	}
	var requested uint32
	var mapping [4]uint32
	if ioctl(uintptr(get(p)), 0x230458, ptr(&requested), 4, uintptr(unsafe.Pointer(&mapping)), 16, ptr(&returned), 0) == 0 {
		return 0
	}
	put(p+12, mapping[0])
	put(p+16, mapping[2])
	surface := createBitmap(1024, 768, 4096, 6, 1, uintptr(mapping[2]))
	if surface == 0 {
		disableSurface(p)
		return 0
	}
	put(p+8, uint32(surface))
	if associateSurface(surface, uintptr(get(p+4)), 0) == 0 {
		disableSurface(p)
		return 0
	}
	return surface
}
func disableSurface(p uintptr) {
	if get(p+8) != 0 {
		deleteSurface(uintptr(get(p + 8)))
		put(p+8, 0)
	}
	if get(p+12) != 0 {
		var returned uint32
		ioctl(uintptr(get(p)), 0x23045c, p+12, 4, 0, 0, ptr(&returned), 0)
		put(p+12, 0)
		put(p+16, 0)
	}
}
func assertMode(p, enabled uintptr) {
	var returned, mode uint32
	if enabled != 0 {
		ioctl(uintptr(get(p)), 0x23040c, ptr(&mode), 4, 0, 0, ptr(&returned), 0)
	} else {
		ioctl(uintptr(get(p)), 0x230410, 0, 0, 0, 0, ptr(&returned), 0)
	}
}
func setPointerShape(surface, mask, color, xlate, xHot, yHot, x, y, rect, flags uintptr) uint32 {
	return 1
}                                             // SPS_DECLINE: GDI software cursor
func movePointer(surface, x, y, rect uintptr) {}

// The 32-bit surface uses fixed RGB masks, with GDI handling dithering.
func ditherColor(p, mode, rgb, output uintptr) uint32           { return 2 }
func setPalette(p, palette, flags, start, count uintptr) uint32 { return 1 }
func getModes(driver, size, output uintptr) uint32 {
	if output == 0 {
		return 188
	}
	if size < 188 {
		return 0
	}
	zero(output, 188)
	wide(output, "trexfb")
	*(*uint16)(unsafe.Pointer(output + 64)) = 0x300
	*(*uint16)(unsafe.Pointer(output + 66)) = 0x300
	*(*uint16)(unsafe.Pointer(output + 68)) = 188
	put(output+72, 0x5c0000)
	put(output+168, 32)
	put(output+172, 1024)
	put(output+176, 768)
	put(output+184, 60)
	return 188
}
