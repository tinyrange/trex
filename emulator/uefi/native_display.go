package uefi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"j5.nz/cc/display"
	"j5.nz/cc/hypervisor"
)

var errNativeShutdown = errors.New("guest powered off")

// AttachGraphicsOutput exposes reserved guest RAM through the shared UEFI GOP.
// Windows can retain this framebuffer through its built-in BasicDisplay driver.
func (n *NativeExecution) AttachGraphicsOutput(width, height uint32) error {
	if n.graphics != nil || n.Display != nil || n.firmware.exited || width == 0 || height == 0 || width > 8192 || height > 8192 {
		return fmt.Errorf("invalid native GOP configuration or boot phase")
	}
	size := uint64(width) * uint64(height) * 4
	m := n.firmware
	address := m.allocate(1, 0, (size+page-1)/page, 0xffffffff)
	if address == 0 {
		return fmt.Errorf("no reserved GOP framebuffer memory")
	}
	f := &Firmware{machine: m, physical: n}
	if err := f.InstallGraphicsOutput(address, n.ram[address-n.base:address-n.base+size], width, height, width); err != nil {
		return err
	}
	n.graphics = f
	return nil
}

func (n *NativeExecution) displayDimensions() (int, int) {
	if n.graphics != nil {
		return int(n.graphics.graphics.width), int(n.graphics.graphics.height)
	}
	if n.Display != nil {
		return n.Display.Dimensions()
	}
	return 0, 0
}

func (n *NativeExecution) displaySnapshotInto(storage []byte) (display.FramebufferUpdate, error) {
	if n.graphics == nil {
		if n.Display == nil {
			return display.FramebufferUpdate{}, fmt.Errorf("native display not attached")
		}
		return n.Display.SnapshotInto(storage)
	}
	g := n.graphics.graphics
	if cap(storage) < len(g.pixels) {
		storage = make([]byte, len(g.pixels))
	}
	storage = storage[:len(g.pixels)]
	copy(storage, g.pixels)
	w, h := int(g.width), int(g.height)
	return display.FramebufferUpdate{Width: w, Height: h, Rect: image.Rect(0, 0, w, h), Pixels: storage}, nil
}

func (n *NativeExecution) advanceDisplay(ctx context.Context) error {
	ex, err := n.Run(ctx)
	if err != nil {
		return err
	}
	if ex.Reason == hypervisor.ExitShutdown {
		return errNativeShutdown
	}
	if ex.Reason != hypervisor.ExitCanceled {
		return fmt.Errorf("native execution stopped: %+v", ex)
	}
	return nil
}

// AttachInput attaches modern virtio PCI keyboard/pointer devices to the native
// bus. The caller must describe their PCI interrupts in the firmware ACPI _PRT.
func (n *NativeExecution) AttachInput(keyboard, pointer hypervisor.InputPCIConfiguration) error {
	if n.pci == nil || n.Keyboard != nil || n.Pointer != nil {
		return fmt.Errorf("input requires a PCI bus without attached input")
	}
	var err error
	n.Keyboard, err = hypervisor.AddInputPCI(n.cpu, n.pci, keyboard)
	if err != nil {
		return err
	}
	n.Pointer, err = hypervisor.AddInputPCI(n.cpu, n.pci, pointer)
	return err
}

// NativeDisplaySession adapts RAMFB and virtio HID to the CC display API. The
// execution owner must serialize session accesses with NativeExecution.Run.
type NativeDisplaySession struct {
	Execution         *NativeExecution
	width, height     int
	generation        uint64
	scratch, previous []byte
}

func (s *NativeDisplaySession) Size() (int, int) { return s.width, s.height }
func (s *NativeDisplaySession) Snapshot(_ image.Rectangle, since uint64, incremental bool) display.FramebufferUpdate {
	n := s.Execution
	f, err := n.displaySnapshotInto(s.scratch)
	if err != nil {
		return display.FramebufferUpdate{}
	}
	s.scratch = f.Pixels
	changedSize := s.width != f.Width || s.height != f.Height
	if changedSize {
		s.previous = make([]byte, len(f.Pixels))
		s.width, s.height = f.Width, f.Height
		if n.Pointer != nil {
			n.Pointer.SetDimensions(uint32(f.Width), uint32(f.Height))
		}
	}
	first, last := 0, f.Height
	stride := f.Width * 4
	if incremental && !changedSize && since == s.generation {
		for first < last && bytes.Equal(s.previous[first*stride:(first+1)*stride], f.Pixels[first*stride:(first+1)*stride]) {
			first++
		}
		for last > first && bytes.Equal(s.previous[(last-1)*stride:last*stride], f.Pixels[(last-1)*stride:last*stride]) {
			last--
		}
	}
	if first == last {
		return display.FramebufferUpdate{Width: f.Width, Height: f.Height, Generation: s.generation}
	}
	copy(s.previous[first*stride:last*stride], f.Pixels[first*stride:last*stride])
	f.Pixels = bytes.Clone(f.Pixels[first*stride : last*stride])
	f.Rect = image.Rect(0, first, f.Width, last)
	s.generation++
	f.Generation = s.generation
	return f
}
func (s *NativeDisplaySession) Changed() <-chan struct{} { return nil }
func (s *NativeDisplaySession) Resize(w, h int) error {
	return fmt.Errorf("native display resize is not supported")
}
func (s *NativeDisplaySession) Key(code uint16, down bool) error {
	if s.Execution.Keyboard == nil {
		return fmt.Errorf("native keyboard not attached")
	}
	return s.Execution.Keyboard.Key(code, down)
}
func (s *NativeDisplaySession) Pointer(x, y uint32, buttons, previous uint8) error {
	if s.Execution.Pointer == nil {
		return fmt.Errorf("native pointer not attached")
	}
	return s.Execution.Pointer.PointerEvent(x, y, buttons, previous)
}
func (s *NativeDisplaySession) Scroll(x, y int32) error {
	if s.Execution.Pointer == nil {
		return fmt.Errorf("native pointer not attached")
	}
	return s.Execution.Pointer.ScrollEvent(x, y)
}
func (s *NativeDisplaySession) SetClipboard(string)              {}
func (s *NativeDisplaySession) GuestClipboard() (string, uint64) { return "", 0 }
