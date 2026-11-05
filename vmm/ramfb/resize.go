package ramfb

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The optional RSZ1 mailbox occupies otherwise unused TRF1 header bytes.
// Host-owned words are requested width (32), height (36), sequence (40).
// Guest-owned words are magic (24), ready (28), completed sequence (44),
// signed result (48), maximum width (52), maximum height (56).
// Both sides publish the sequence last. A successful completion means Windows
// has applied the mode, not merely that its driver has received the request.
// The host accesses this memory only while all guest CPUs are stopped.
const ResizeMagic uint32 = 0x315a5352 // "RSZ1"

const (
	MaxWidth  = 1920
	MaxHeight = 1080
)

var (
	ErrResizeUnavailable = errors.New("guest display resize is not ready")
	ErrResizeSuperseded  = errors.New("display resize was superseded")
)

// ResizeLimits reports the guest's currently advertised resize support. Fixed
// TRF1 drivers and firmware framebuffers leave these words zero and are never
// treated as supporting live mode changes.
func ResizeLimits(memory []byte) (width, height int, ready bool) {
	if len(memory) < Pixels || binary.LittleEndian.Uint32(memory) != Magic ||
		binary.LittleEndian.Uint32(memory[24:]) != ResizeMagic || binary.LittleEndian.Uint32(memory[28:]) != 1 {
		return 0, 0, false
	}
	w, h := binary.LittleEndian.Uint32(memory[52:]), binary.LittleEndian.Uint32(memory[56:])
	format := binary.LittleEndian.Uint32(memory[20:])
	stride := uint64(w) * 4
	if format == 2 {
		stride = (uint64(w) + 15) / 16 * 2 // Win16 word-aligned monochrome rows
	}
	if !validPixelLayout(uint64(w), uint64(h), stride, format, len(memory)-Pixels) {
		return 0, 0, false
	}
	return int(w), int(h), true
}

// RequestResize publishes a new request without altering the active framebuffer
// or claiming guest completion. A newer request supersedes any unfinished one.
func RequestResize(memory []byte, width, height int) (uint32, error) {
	maxWidth, maxHeight, ready := ResizeLimits(memory)
	if !ready {
		return 0, ErrResizeUnavailable
	}
	if width <= 0 || height <= 0 || width > maxWidth || height > maxHeight {
		return 0, fmt.Errorf("display size %dx%d is outside guest limits 1..%dx1..%d", width, height, maxWidth, maxHeight)
	}
	sequence := binary.LittleEndian.Uint32(memory[40:]) + 1
	// Zero is reserved for no request. Avoid accidentally matching the previous
	// completion when the 32-bit sequence wraps.
	completed := binary.LittleEndian.Uint32(memory[44:])
	for sequence == 0 || sequence == completed {
		sequence++
	}
	binary.LittleEndian.PutUint32(memory[32:], uint32(width))
	binary.LittleEndian.PutUint32(memory[36:], uint32(height))
	binary.LittleEndian.PutUint32(memory[40:], sequence)
	return sequence, nil
}

// ResizeComplete rejects stale acknowledgements and checks the committed layout
// before reporting success. A guest result other than zero is a rejection,
// including a Windows request to restart rather than resize the live desktop.
func ResizeComplete(memory []byte, sequence uint32, width, height int) (bool, error) {
	if _, _, ready := ResizeLimits(memory); !ready {
		return false, ErrResizeUnavailable
	}
	if sequence == 0 || binary.LittleEndian.Uint32(memory[40:]) != sequence {
		return false, ErrResizeSuperseded
	}
	if binary.LittleEndian.Uint32(memory[44:]) != sequence {
		return false, nil
	}
	if result := int32(binary.LittleEndian.Uint32(memory[48:])); result != 0 {
		return false, fmt.Errorf("guest rejected live display resize (result %d)", result)
	}
	w, h := binary.LittleEndian.Uint32(memory[8:]), binary.LittleEndian.Uint32(memory[12:])
	stride := binary.LittleEndian.Uint32(memory[16:])
	if binary.LittleEndian.Uint32(memory[4:]) != 1 || w != uint32(width) || h != uint32(height) ||
		!validPixelLayout(uint64(w), uint64(h), uint64(stride), binary.LittleEndian.Uint32(memory[20:]), len(memory)-Pixels) {
		return false, fmt.Errorf("guest acknowledged resize without committing the requested framebuffer")
	}
	return true, nil
}
