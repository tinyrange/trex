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

// AbsolutePointerSource reports whether a guest currently accepts absolute
// pointer coordinates. The mode may change as guest drivers start or stop.
type AbsolutePointerSource interface {
	AbsolutePointer(context.Context) (bool, error)
}
