package uefi

import (
	"fmt"
	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/windows/guid"
)

const graphicsOutputGUID = "{9042A9DE-23DC-4A38-96FB-7ADED080516A}"

type graphicsOutput struct {
	protocol, info        uint64
	width, height, stride uint64
	pixels                []byte
}

// InstallGraphicsOutput exposes one BGRX mode over caller-owned framebuffer
// bytes. PhysicalBase is the guest mapping, independent of host addresses.
func (f *Firmware) InstallGraphicsOutput(physicalBase uint64, pixels []byte, width, height, stride uint32) error {
	if f.graphics != nil || width == 0 || height == 0 || stride < width || uint64(stride) > ^uint64(0)/uint64(height)/4 || uint64(stride)*uint64(height)*4 > uint64(len(pixels)) || physicalBase > ^uint64(0)-uint64(len(pixels)) {
		return fmt.Errorf("uefi: invalid graphics output")
	}
	m := f.machine
	p := m.allocate(0, 4, 1, 0)
	if p == 0 {
		return fmt.Errorf("uefi: no graphics protocol memory")
	}
	mode, info := p+64, p+128
	m.u64(p, m.gate("GOP.QueryMode"))
	m.u64(p+8, m.gate("GOP.SetMode"))
	m.u64(p+16, m.gate("GOP.Blt"))
	m.u64(p+24, mode)
	m.u32(mode, 1)
	m.u64(mode+8, info)
	m.u64(mode+16, 36)
	m.u64(mode+24, physicalBase)
	m.u64(mode+32, uint64(stride)*uint64(height)*4)
	m.u32(info, 0)
	m.u32(info+4, width)
	m.u32(info+8, height)
	m.u32(info+12, 1)
	m.u32(info+32, stride)
	// The graphics handle also identifies the physical framebuffer device.
	// Windows enumerates GOP handles only when DevicePath can be opened.
	identifier, _ := guid.Parse("{54525846-5241-4D46-8000-000000000001}")
	path := []byte{1, 4, 20, 0}
	path = append(path, identifier[:]...)
	path = append(path, 0x7f, 0xff, 4, 0)
	m.put(p+192, path)
	m.protocols[p] = map[string]uint64{graphicsOutputGUID: p, devicePathGUID: p + 192}
	f.graphics = &graphicsOutput{p, info, uint64(width), uint64(height), uint64(stride), pixels[:uint64(stride)*uint64(height)*4]}
	return m.err
}
func (f *Firmware) graphicsCall(name string, a [10]uint64) (uint64, error) {
	m, g := f.machine, f.graphics
	if g == nil || a[0] != g.protocol {
		return invalidParameter, nil
	}
	switch name {
	case "GOP.QueryMode":
		if uint32(a[1]) != 0 || a[2] == 0 || a[3] == 0 {
			return invalidParameter, nil
		}
		p := m.allocate(0, 4, 1, 0)
		if p == 0 {
			return outOfResources, nil
		}
		m.put(p, m.get(g.info, 36))
		m.u64(a[2], 36)
		m.u64(a[3], p)
	case "GOP.SetMode":
		if uint32(a[1]) != 0 {
			return unsupported, nil
		}
		clear(g.pixels)
	case "GOP.Blt":
		op, sx, sy, dx, dy, w, h, delta := uint64(uint32(a[2])), a[3], a[4], a[5], a[6], a[7], a[8], a[9]
		if op > 3 || w == 0 || h == 0 || w > g.width || h > g.height {
			return invalidParameter, nil
		}
		screen := func(x, y uint64) bool { return x <= g.width-w && y <= g.height-h }
		if (op == 0 || op == 2 || op == 3) && !screen(dx, dy) || (op == 1 || op == 3) && !screen(sx, sy) {
			return invalidParameter, nil
		}
		if delta == 0 {
			delta = w * 4
		}
		bufferX, bufferY := sx, sy
		if op == 1 {
			bufferX, bufferY = dx, dy
		}
		var bufferStart uint64
		if op == 1 || op == 2 {
			if bufferX > ^uint64(0)/4-w || delta < (bufferX+w)*4 || bufferY > ^uint64(0)-h || bufferY+h > ^uint64(0)/delta {
				return invalidParameter, nil
			}
			span := (bufferY+h-1)*delta + (bufferX+w)*4
			if span > m.opts.Memory || a[1] > ^uint64(0)-span {
				return invalidParameter, nil
			}
			access := cpu.Read
			if op == 1 {
				access = cpu.Write
			}
			if err := m.serviceMemory().CheckMemory(a[1], int(span), access); err != nil {
				return invalidParameter, err
			}
			bufferStart = a[1] + bufferY*delta + bufferX*4
		}
		// A rectangle-sized copy preserves overlapping video-to-video transfers.
		b := make([]byte, int(w*h*4))
		switch op {
		case 0:
			pixel := m.get(a[1], 4)
			if m.err != nil {
				return invalidParameter, m.err
			}
			for i := 0; i < len(b); i += 4 {
				copy(b[i:], pixel)
			}
		case 1, 3:
			for y := uint64(0); y < h; y++ {
				copy(b[y*w*4:(y+1)*w*4], g.pixels[((sy+y)*g.stride+sx)*4:((sy+y)*g.stride+sx+w)*4])
			}
		case 2:
			for y := uint64(0); y < h; y++ {
				if err := m.serviceMemory().ReadMemory(bufferStart+y*delta, b[y*w*4:(y+1)*w*4], cpu.Read); err != nil {
					return invalidParameter, err
				}
			}
		}
		for y := uint64(0); y < h; y++ {
			row := b[y*w*4 : (y+1)*w*4]
			if op == 1 {
				m.put(bufferStart+y*delta, row)
			} else {
				copy(g.pixels[((dy+y)*g.stride+dx)*4:], row)
			}
		}
	}
	return 0, m.err
}
