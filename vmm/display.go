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

// ReusableDisplaySource may capture into a caller-owned framebuffer to avoid
// allocating on each poll. The caller lends dst exclusively until the call
// returns. The result may be a replacement and must not alias guest memory.
type ReusableDisplaySource interface {
	CaptureInto(ctx context.Context, dst *image.RGBA) (*image.RGBA, error)
}

// ResizeDisplaySource optionally changes the guest's desktop resolution. Resize
// returns nil only after the guest has applied the requested pixel dimensions;
// rejecting a mode or canceling the request returns an error. It must honor ctx
// and may run concurrently with Capture and Input. Frontends continue presenting
// captured geometry while a request is pending.
type ResizeDisplaySource interface {
	Resize(ctx context.Context, width, height int) error
}

// DisplayResizeReadiness optionally delays resize requests until a guest driver
// is ready. Sources implementing ResizeDisplaySource without this interface are
// considered ready. Frontends recheck readiness as a guest boots.
type DisplayResizeReadiness interface {
	ResizeReady(context.Context) (bool, error)
}

// AbsolutePointerSource reports whether a guest currently accepts absolute
// pointer coordinates. The mode may change as guest drivers start or stop.
type AbsolutePointerSource interface {
	AbsolutePointer(context.Context) (bool, error)
}
