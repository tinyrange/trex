package uefi

import (
	"bytes"
	"fmt"
	"image"
	"j5.nz/cc/display"
	"j5.nz/cc/hypervisor"
)

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
	if n.Display == nil {
		return display.FramebufferUpdate{}
	}
	f, err := n.Display.SnapshotInto(s.scratch)
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
