package vmm

import (
	"context"
	"image"
)

// DisplaySource provides an owned framebuffer and input transitions without native
// window, socket, or file handles. Capture must not alias mutable guest memory.
type DisplaySource interface {
	Capture(context.Context) (*image.RGBA, error)
	Input(context.Context, Input) error
}
