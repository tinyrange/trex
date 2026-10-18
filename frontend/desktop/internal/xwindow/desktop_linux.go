//go:build linux

package xwindow

import (
	"github.com/ebitengine/purego"
	"unsafe"
)

var (
	xGrabPointer    func(uintptr, uintptr, int32, uint32, int32, int32, uintptr, uintptr, uint64) int32
	xUngrabPointer  func(uintptr, uint64) int32
	xGrabKeyboard   func(uintptr, uintptr, int32, int32, int32, uint64) int32
	xUngrabKeyboard func(uintptr, uint64) int32
	xWarpPointer    func(uintptr, uintptr, uintptr, int32, int32, uint32, uint32, int32, int32) int32
	xSendEvent      func(uintptr, uintptr, int32, int64, unsafe.Pointer) int32
	xFlush          func(uintptr) int32
	xCreateBitmap   func(uintptr, uintptr, *byte, uint32, uint32) uintptr
	xCreateCursor   func(uintptr, uintptr, uintptr, *xColor, *xColor, uint32, uint32) uintptr
	xFreePixmap     func(uintptr, uintptr) int32
	xFreeCursor     func(uintptr, uintptr) int32
	xDefineCursor   func(uintptr, uintptr, uintptr) int32
	xUndefineCursor func(uintptr, uintptr) int32
)

type xColor struct {
	Pixel            uint64
	Red, Green, Blue uint16
	Flags, Pad       byte
}

func registerDesktopFunctions() {
	purego.RegisterLibFunc(&xCreateBitmap, x11lib, "XCreateBitmapFromData")
	purego.RegisterLibFunc(&xCreateCursor, x11lib, "XCreatePixmapCursor")
	purego.RegisterLibFunc(&xFreePixmap, x11lib, "XFreePixmap")
	purego.RegisterLibFunc(&xFreeCursor, x11lib, "XFreeCursor")
	purego.RegisterLibFunc(&xDefineCursor, x11lib, "XDefineCursor")
	purego.RegisterLibFunc(&xUndefineCursor, x11lib, "XUndefineCursor")
	purego.RegisterLibFunc(&xGrabPointer, x11lib, "XGrabPointer")
	purego.RegisterLibFunc(&xUngrabPointer, x11lib, "XUngrabPointer")
	purego.RegisterLibFunc(&xGrabKeyboard, x11lib, "XGrabKeyboard")
	purego.RegisterLibFunc(&xUngrabKeyboard, x11lib, "XUngrabKeyboard")
	purego.RegisterLibFunc(&xWarpPointer, x11lib, "XWarpPointer")
	purego.RegisterLibFunc(&xSendEvent, x11lib, "XSendEvent")
	purego.RegisterLibFunc(&xFlush, x11lib, "XFlush")
}
func (w *x11Window) SetTitle(s string) {
	xStoreName(w.display, w.window, cString(s))
	xFlush(w.display)
}
func (w *x11Window) SetCaptured(on bool) bool {
	if w.captured == on {
		return true
	}
	if !on {
		xUngrabPointer(w.display, 0)
		xUngrabKeyboard(w.display, 0)
		w.SetCursorHidden(false)
		w.captured = false
		xFlush(w.display)
		return true
	}
	if xGrabPointer(w.display, w.window, 0, buttonPressMask|buttonReleaseMask|pointerMotionMask, 1, 1, w.window, 0, 0) != 0 {
		return false
	}
	if xGrabKeyboard(w.display, w.window, 0, 1, 1, 0) != 0 {
		xUngrabPointer(w.display, 0)
		return false
	}
	w.SetCursorHidden(true)
	w.captured = true
	w.warpCenter()
	w.motionX, w.motionY = w.warpX, w.warpY
	return true
}
func (w *x11Window) warpCenter() {
	width, height := w.BackingSize()
	w.warpX, w.warpY = int32(width/2), int32(height/2)
	w.warped = true
	xWarpPointer(w.display, 0, w.window, 0, 0, 0, 0, w.warpX, w.warpY)
	xFlush(w.display)
}
func (w *x11Window) SetFullscreen(on bool) {
	action := uint64(0)
	if on {
		action = 1
	}
	ev := xclientMessage{Type: clientMessage, Display: w.display, Window: w.window, MessageType: xInternAtom(w.display, cString("_NET_WM_STATE"), 0), Format: 32}
	ev.Data = [5]uint64{action, uint64(xInternAtom(w.display, cString("_NET_WM_STATE_FULLSCREEN"), 0)), 0, 1, 0}
	xSendEvent(w.display, xRootWindow(w.display, xDefaultScreen(w.display)), 0, (1<<19)|(1<<20), unsafe.Pointer(&ev))
	xFlush(w.display)
}

// SetCursorHidden affects this window only; it never grabs or warps the pointer.
func (w *x11Window) SetCursorHidden(hidden bool) {
	if hidden == w.cursorHidden {
		return
	}
	w.cursorHidden = hidden
	if !hidden {
		xUndefineCursor(w.display, w.window)
		return
	}
	if w.hiddenCursor == 0 {
		var blank byte
		bitmap := xCreateBitmap(w.display, w.window, &blank, 1, 1)
		if bitmap != 0 {
			c := xColor{}
			w.hiddenCursor = xCreateCursor(w.display, bitmap, bitmap, &c, &c, 0, 0)
			xFreePixmap(w.display, bitmap)
		}
	}
	if w.hiddenCursor != 0 {
		xDefineCursor(w.display, w.window, w.hiddenCursor)
	}
}
