//go:build linux

package xwindow

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"strconv"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/tinyrange/gowin/gl"
)

const (
	glxRGBA         = 4
	glxDoubleBuffer = 5
	glxDepthSize    = 12
	glxStencilSize  = 13
	glxNone         = 0

	// GLX_ARB_create_context constants
	glxContextMajorVersionArb   = 0x2091
	glxContextMinorVersionArb   = 0x2092
	glxContextFlagsArb          = 0x2094
	glxContextCoreProfileBitArb = 0x00000001

	inputOutput = 1

	exposureMask        = 1 << 15
	structureNotifyMask = 1 << 17
	keyPressMask        = 1 << 0
	keyReleaseMask      = 1 << 1
	buttonPressMask     = 1 << 2
	buttonReleaseMask   = 1 << 3
	pointerMotionMask   = 1 << 6

	focusChangeMask = 1 << 21
	focusIn         = 9
	focusOut        = 10
	clientMessage   = 33
	destroyNotify   = 17
	keyPress        = 2
	keyRelease      = 3
	buttonPress     = 4
	buttonRelease   = 5
	motionNotify    = 6

	// X11 modifier masks.
	x11ShiftMask   = 1 << 0
	x11ControlMask = 1 << 2
	x11Mod1Mask    = 1 << 3 // typically Alt
	x11Mod4Mask    = 1 << 6 // typically Super/Win
)

type XVisualInfo struct {
	Visual       uintptr
	VisualID     uint
	Screen       int32
	Depth        int32
	Class        int32
	RedMask      uint64
	GreenMask    uint64
	BlueMask     uint64
	ColormapSize int32
	BitsPerRGB   int32
	MapEntries   int32
	pad          int32
}

type xclientMessage struct {
	Type        int32
	Serial      uint64
	SendEvent   int32
	Display     uintptr
	Window      uintptr
	MessageType uintptr
	Format      int32
	Data        [5]uint64
}

// xEvent is an aligned XEvent-sized buffer (192 bytes on 64-bit Xlib).
// We use uint64 words to guarantee 8-byte alignment for unsafe casts.
type xEvent [24]uint64

type xFocusEvent struct {
	Type            int32
	Serial          uint64
	SendEvent       int32
	Display, Window uintptr
	Mode, Detail    int32
}

type xKeyEvent struct {
	Type       int32
	_          int32 // padding (align Serial)
	Serial     uint64
	SendEvent  int32 // X11 Bool
	_          int32 // padding (align pointers)
	Display    uintptr
	Window     uintptr
	Root       uintptr
	Subwindow  uintptr
	Time       uint64 // X11 Time is unsigned long in Xlib
	X          int32
	Y          int32
	XRoot      int32
	YRoot      int32
	State      uint32
	KeyCode    uint32
	SameScreen int32
}

type xButtonEvent struct {
	Type       int32
	_          int32 // padding (align Serial)
	Serial     uint64
	SendEvent  int32 // X11 Bool
	_          int32 // padding (align pointers)
	Display    uintptr
	Window     uintptr
	Root       uintptr
	Subwindow  uintptr
	Time       uint64 // X11 Time is unsigned long in Xlib
	X          int32
	Y          int32
	XRoot      int32
	YRoot      int32
	State      uint32
	Button     uint32
	SameScreen int32
}

var (
	x11lib uintptr
	gllib  uintptr

	xOpenDisplay           func(*byte) uintptr
	xDefaultScreen         func(uintptr) int32
	xRootWindow            func(uintptr, int32) uintptr
	xCreateColormap        func(uintptr, uintptr, uintptr, int32) uintptr
	xCreateWindow          func(uintptr, uintptr, int32, int32, uint32, uint32, uint32, int32, uint32, uintptr, uint64, unsafe.Pointer) uintptr
	xMapWindow             func(uintptr, uintptr) int32
	xStoreName             func(uintptr, uintptr, *byte) int32
	xInternAtom            func(uintptr, *byte, int32) uintptr
	xSetWMProtocols        func(uintptr, uintptr, *uintptr, int32) int32
	xSelectInput           func(uintptr, uintptr, int64)
	xPending               func(uintptr) int32
	xNextEvent             func(uintptr, unsafe.Pointer)
	xGetGeometry           func(uintptr, uintptr, *uintptr, *int32, *int32, *uint32, *uint32, *uint32, *uint32) int32
	xDestroyWindow         func(uintptr, uintptr) int32
	xCloseDisplay          func(uintptr) int32
	xQueryPointer          func(uintptr, uintptr, *uintptr, *uintptr, *int32, *int32, *int32, *int32, *uint32) int32
	xDisplayWidth          func(uintptr, int32) int32
	xDisplayWidthMM        func(uintptr, int32) int32
	xDisplayHeight         func(uintptr, int32) int32
	xDisplayHeightMM       func(uintptr, int32) int32
	xResourceManagerString func(uintptr) *byte
	xGetSelectionOwnerCore func(uintptr, uintptr) uintptr
	xGetWindowPropertyCore func(uintptr, uintptr, uintptr, int64, int64, int32, uintptr, *uintptr, *int32, *uint64, *uint64, **byte) int32
	xFreeCore              func(unsafe.Pointer) int32
	xLookupKeysym          func(*xKeyEvent, int32) uint32

	glxChooseVisual            func(uintptr, int32, *int32) *XVisualInfo
	glxCreateContext           func(uintptr, *XVisualInfo, uintptr, int32) uintptr
	glxMakeCurrent             func(uintptr, uintptr, uintptr) int32
	glxSwapBuffers             func(uintptr, uintptr)
	glxDestroyContext          func(uintptr, uintptr)
	glxChooseFBConfig          func(uintptr, int32, *int32, *int32) *uintptr
	glxGetVisualFromFBConfig   func(uintptr, uintptr) *XVisualInfo
	glxCreateContextAttribsARB func(uintptr, uintptr, uintptr, int32, *int32) uintptr
	glXGetProcAddressARB       func(*byte) unsafe.Pointer
)

type x11Window struct {
	display          uintptr
	window           uintptr
	ctx              uintptr
	wmDelete         uintptr
	running          bool
	focused          bool
	captured         bool
	warpX, warpY     int32
	warped           bool
	motionX, motionY int32
	hiddenCursor     uintptr
	cursorHidden     bool
	scale            float32
	keyStates        map[Key]KeyState
	buttonStates     map[Button]ButtonState
	inputEvents      []InputEvent
}

func New(title string, width, height int, _ bool) (Window, error) {
	runtime.LockOSThread()
	if err := ensureLibs(); err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}

	dpy := xOpenDisplay(nil)
	if dpy == 0 {
		runtime.UnlockOSThread()
		return nil, errors.New("XOpenDisplay failed")
	}

	screen := xDefaultScreen(dpy)
	root := xRootWindow(dpy, screen)

	// Try to use GLX_ARB_create_context for OpenGL 3.0+
	var visual *XVisualInfo
	var fbConfig uintptr
	var ctx uintptr

	// First, try FBConfig-based approach for GL 3.0+
	if glxChooseFBConfig != nil {
		fbAttribs := []int32{
			0x8011, // GLX_X_RENDERABLE
			1,      // True
			0x8012, // GLX_DRAWABLE_TYPE
			0x8001, // GLX_WINDOW_BIT
			0x8013, // GLX_RENDER_TYPE
			0x8011, // GLX_RGBA_BIT
			0x8014, // GLX_X_VISUAL_TYPE
			0x8012, // GLX_TRUE_COLOR
			0x8002, // GLX_DOUBLEBUFFER
			1,      // True
			0x8015, // GLX_RED_SIZE
			8,
			0x8016, // GLX_GREEN_SIZE
			8,
			0x8017, // GLX_BLUE_SIZE
			8,
			0x8018, // GLX_ALPHA_SIZE
			8,
			0x8019, // GLX_DEPTH_SIZE
			24,
			glxStencilSize,
			8,
			glxNone,
		}
		var numConfigs int32
		fbConfigs := glxChooseFBConfig(dpy, screen, &fbAttribs[0], &numConfigs)
		if fbConfigs != nil {
			defer xFreeCore(unsafe.Pointer(fbConfigs))
		}
		if fbConfigs != nil && numConfigs > 0 {
			// Use first FBConfig
			fbConfig = *fbConfigs
			visual = glxGetVisualFromFBConfig(dpy, fbConfig)
			if visual != nil && glxCreateContextAttribsARB != nil {
				// Create OpenGL 3.0 context
				ctxAttribs := []int32{
					glxContextMajorVersionArb, 3,
					glxContextMinorVersionArb, 0,
					glxContextFlagsArb, glxContextCoreProfileBitArb,
					glxNone,
				}
				ctx = glxCreateContextAttribsARB(dpy, fbConfig, 0, 1, &ctxAttribs[0])
			}
		}
	}

	// Fallback to legacy path if GL 3.0 context creation failed
	if ctx == 0 {
		attrs := []int32{glxRGBA, glxDoubleBuffer, glxDepthSize, 24, glxStencilSize, 8, glxNone}
		visual = glxChooseVisual(dpy, screen, &attrs[0])
		if visual == nil {
			xCloseDisplay(dpy)
			runtime.UnlockOSThread()
			return nil, errors.New("glXChooseVisual failed")
		}
		ctx = glxCreateContext(dpy, visual, 0, 1)
		if ctx == 0 {
			xCloseDisplay(dpy)
			runtime.UnlockOSThread()
			return nil, errors.New("glXCreateContext failed")
		}
	}

	if visual == nil {
		xCloseDisplay(dpy)
		runtime.UnlockOSThread()
		return nil, errors.New("failed to get visual")
	}

	cmap := xCreateColormap(dpy, root, visual.Visual, 0)

	var swa xSetWindowAttributes
	swa.Colormap = cmap
	swa.EventMask = exposureMask | structureNotifyMask | keyPressMask | keyReleaseMask | buttonPressMask | buttonReleaseMask | pointerMotionMask | focusChangeMask

	const (
		cwColormap    = 1 << 13
		cwEventMask   = 1 << 11
		cwBorderPixel = 1 << 3
	)

	win := xCreateWindow(
		dpy, root,
		0, 0,
		uint32(width), uint32(height),
		0,
		visual.Depth,
		inputOutput,
		visual.Visual,
		cwBorderPixel|cwColormap|cwEventMask,
		unsafe.Pointer(&swa),
	)
	if win == 0 {
		if ctx != 0 {
			glxDestroyContext(dpy, ctx)
		}
		xCloseDisplay(dpy)
		runtime.UnlockOSThread()
		return nil, errors.New("XCreateWindow failed")
	}
	xSelectInput(dpy, win, swa.EventMask)

	titleBytes := append([]byte(title), 0)
	xStoreName(dpy, win, &titleBytes[0])
	xMapWindow(dpy, win)

	wmDelete := xInternAtom(dpy, cString("WM_DELETE_WINDOW"), 0)
	xSetWMProtocols(dpy, win, &wmDelete, 1)

	if glxMakeCurrent(dpy, win, ctx) == 0 {
		glxDestroyContext(dpy, ctx)
		xDestroyWindow(dpy, win)
		xCloseDisplay(dpy)
		runtime.UnlockOSThread()
		return nil, errors.New("glXMakeCurrent failed")
	}

	// Calculate scale factor from DPI
	scale := calculateScale(dpy, screen)

	w := &x11Window{
		display:      dpy,
		window:       win,
		ctx:          ctx,
		wmDelete:     wmDelete,
		running:      true,
		scale:        scale,
		keyStates:    make(map[Key]KeyState),
		buttonStates: make(map[Button]ButtonState),
		inputEvents:  make([]InputEvent, 0, 256),
	}
	return w, nil
}

func (w *x11Window) GL() (gl.OpenGL, error) {
	return gl.Load()
}

func (w *x11Window) Close() {
	if w.display != 0 {
		w.SetCaptured(false)
		if w.hiddenCursor != 0 {
			xFreeCursor(w.display, w.hiddenCursor)
			w.hiddenCursor = 0
		}
	}
	if w.ctx != 0 {
		glxMakeCurrent(w.display, 0, 0)
		glxDestroyContext(w.display, w.ctx)
		w.ctx = 0
	}
	if w.window != 0 {
		xDestroyWindow(w.display, w.window)
		w.window = 0
	}
	if w.display != 0 {
		xCloseDisplay(w.display)
		w.display = 0
	}
	w.running = false
	runtime.UnlockOSThread()
}

func (w *x11Window) Poll() bool {
	if !w.running {
		return false
	}

	// Transition states: Pressed -> Down, Released -> Up
	for key, state := range w.keyStates {
		if state == KeyStatePressed {
			w.keyStates[key] = KeyStateDown
		} else if state == KeyStateRepeated {
			// Repeated is a one-frame pulse indicating an OS key-repeat event.
			// If we don't transition it, downstream consumers may treat it as a
			// per-frame trigger and spam input.
			w.keyStates[key] = KeyStateDown
		} else if state == KeyStateReleased {
			w.keyStates[key] = KeyStateUp
		}
	}
	for button, state := range w.buttonStates {
		if state == ButtonStatePressed {
			w.buttonStates[button] = ButtonStateDown
		} else if state == ButtonStateReleased {
			w.buttonStates[button] = ButtonStateUp
		}
	}

	moved := false
	for xPending(w.display) > 0 {
		var ev xEvent
		xNextEvent(w.display, unsafe.Pointer(&ev[0]))
		etype := *(*int32)(unsafe.Pointer(&ev[0]))
		switch etype {
		case focusIn:
			w.focused = true
		case focusOut:
			mode := (*xFocusEvent)(unsafe.Pointer(&ev[0])).Mode
			if mode == 1 || mode == 2 {
				break
			} // keyboard grab notifications are not actual focus loss
			w.focused = false
			w.SetCaptured(false)
			w.inputEvents = append(w.inputEvents, InputEvent{Type: InputEventFocusLost})
			clear(w.keyStates)
			clear(w.buttonStates)
		case clientMessage:
			cm := (*xclientMessage)(unsafe.Pointer(&ev[0]))
			if cm.Format == 32 && cm.Data[0] == uint64(w.wmDelete) {
				w.running = false
			}
		case destroyNotify:
			w.running = false
		case keyPress:
			kev := (*xKeyEvent)(unsafe.Pointer(&ev[0]))
			key := w.keycodeToKey(kev)
			if key != KeyUnknown {
				// Treat missing entries as Up (map default is 0 which equals Pressed).
				prev := w.GetKeyState(key)
				mods := x11StateToMods(kev.State)
				isRepeat := !(prev == KeyStateUp || prev == KeyStateReleased)
				w.inputEvents = append(w.inputEvents, InputEvent{
					Type:   InputEventKeyDown,
					Key:    key,
					Repeat: isRepeat,
					Mods:   mods,
				})

				// Best-effort text generation for printable ASCII keys.
				// This enables terminals on linux without requiring XLookupString.
				if xLookupKeysym != nil && (mods&ModCtrl) == 0 {
					idx := int32(0)
					if (kev.State & x11ShiftMask) != 0 {
						idx = 1
					}
					ks := xLookupKeysym(kev, idx)
					if ks >= 0x20 && ks < 0x7f {
						w.inputEvents = append(w.inputEvents, InputEvent{
							Type: InputEventText,
							Text: string(rune(ks)),
							Mods: mods,
						})
					}
				}

				if prev == KeyStateUp || prev == KeyStateReleased {
					w.keyStates[key] = KeyStatePressed
				} else {
					w.keyStates[key] = KeyStateRepeated
				}
			}
		case keyRelease:
			kev := (*xKeyEvent)(unsafe.Pointer(&ev[0]))
			key := w.keycodeToKey(kev)
			if key != KeyUnknown {
				w.inputEvents = append(w.inputEvents, InputEvent{
					Type: InputEventKeyUp,
					Key:  key,
					Mods: x11StateToMods(kev.State),
				})
				w.keyStates[key] = KeyStateReleased
			}
		case buttonPress:
			bev := (*xButtonEvent)(unsafe.Pointer(&ev[0]))
			// X11 uses buttons 4/5 for scroll wheel up/down.
			// Emit a scroll event rather than treating these as mouse buttons.
			if bev.Button == 4 || bev.Button == 5 {
				dy := float32(-1)
				if bev.Button == 4 {
					dy = 1
				}
				w.inputEvents = append(w.inputEvents, InputEvent{
					Type:       InputEventScroll,
					ScrollY:    dy,
					RawScrollY: dy,
					MouseX:     float32(bev.X),
					MouseY:     float32(bev.Y),
					Mods:       x11StateToMods(bev.State),
				})
				break
			}
			if button := w.buttonToButton(bev.Button); button >= ButtonLeft && button <= Button5 {
				w.buttonStates[button] = ButtonStatePressed
				w.inputEvents = append(w.inputEvents, InputEvent{
					Type:        InputEventMouseDown,
					Button:      button,
					ButtonValid: true,
					Mods:        x11StateToMods(bev.State),
					MouseX:      float32(bev.X),
					MouseY:      float32(bev.Y),
				})
			}
		case buttonRelease:
			bev := (*xButtonEvent)(unsafe.Pointer(&ev[0]))
			// Ignore button 4/5 releases (scroll wheel).
			if bev.Button == 4 || bev.Button == 5 {
				break
			}
			if button := w.buttonToButton(bev.Button); button >= ButtonLeft && button <= Button5 {
				w.buttonStates[button] = ButtonStateReleased
				w.inputEvents = append(w.inputEvents, InputEvent{
					Type:        InputEventMouseUp,
					Button:      button,
					ButtonValid: true,
					Mods:        x11StateToMods(bev.State),
					MouseX:      float32(bev.X),
					MouseY:      float32(bev.Y),
				})
			}
		case motionNotify:
			mev := (*xButtonEvent)(unsafe.Pointer(&ev[0]))
			if w.captured {
				if w.warped && mev.X == w.warpX && mev.Y == w.warpY {
					w.warped = false
					w.motionX, w.motionY = mev.X, mev.Y
					break
				}
				w.inputEvents = append(w.inputEvents, InputEvent{Type: InputEventMouseMove, MouseDeltaX: float32(mev.X - w.motionX), MouseDeltaY: float32(mev.Y - w.motionY)})
				w.motionX, w.motionY = mev.X, mev.Y
				moved = true
				break
			}
			w.inputEvents = append(w.inputEvents, InputEvent{
				Type:   InputEventMouseMove,
				Mods:   x11StateToMods(mev.State),
				MouseX: float32(mev.X),
				MouseY: float32(mev.Y),
			})
		}
	}
	if moved && w.captured && !w.warped {
		w.warpCenter()
	}
	return w.running
}

func (w *x11Window) Swap() {
	if w.display != 0 && w.window != 0 {
		glxSwapBuffers(w.display, w.window)
	}
}

func (w *x11Window) BackingSize() (int, int) {
	var root uintptr
	var x, y int32
	var width, height uint32
	var border, depth uint32
	if xGetGeometry(w.display, w.window, &root, &x, &y, &width, &height, &border, &depth) == 0 {
		return 0, 0
	}
	return int(width), int(height)
}

func (w *x11Window) Cursor() (float32, float32) {
	var root, child uintptr
	var rootX, rootY, winX, winY int32
	var mask uint32
	if xQueryPointer(w.display, w.window, &root, &child, &rootX, &rootY, &winX, &winY, &mask) == 0 {
		return 0, 0
	}
	return float32(winX), float32(winY)
}

func (w *x11Window) Scale() float32 {
	return w.scale
}

func (w *x11Window) GetKeyState(key Key) KeyState {
	if state, ok := w.keyStates[key]; ok {
		return state
	}
	return KeyStateUp
}

func (w *x11Window) GetButtonState(button Button) ButtonState {
	if state, ok := w.buttonStates[button]; ok {
		return state
	}
	return ButtonStateUp
}

func (w *x11Window) DrainInputEvents() []InputEvent {
	if w == nil || len(w.inputEvents) == 0 {
		return nil
	}
	out := make([]InputEvent, len(w.inputEvents))
	copy(out, w.inputEvents)
	w.inputEvents = w.inputEvents[:0]
	return out
}

func (w *x11Window) TextInput() string {
	return ""
}

func x11StateToMods(state uint32) KeyMods {
	var m KeyMods
	if (state & x11ShiftMask) != 0 {
		m |= ModShift
	}
	if (state & x11ControlMask) != 0 {
		m |= ModCtrl
	}
	if (state & x11Mod1Mask) != 0 {
		m |= ModAlt
	}
	if (state & x11Mod4Mask) != 0 {
		m |= ModSuper
	}
	return m
}

// keycodeToKey converts an X11 keycode to our Key enum
func (w *x11Window) keycodeToKey(kev *xKeyEvent) Key {
	if xLookupKeysym == nil {
		return KeyUnknown
	}

	// Use XLookupKeysym with index 0 (no modifiers)
	keysym := xLookupKeysym(kev, 0)
	if keysym == 0 {
		return KeyUnknown
	}

	// Map X11 keysyms to our Key enum
	// X11 keysym values are defined in X11/keysymdef.h
	switch keysym {
	// Letters (case-insensitive, X11 provides both)
	case 0x0061, 0x0041: // 'a' or 'A'
		return KeyA
	case 0x0062, 0x0042: // 'b' or 'B'
		return KeyB
	case 0x0063, 0x0043: // 'c' or 'C'
		return KeyC
	case 0x0064, 0x0044: // 'd' or 'D'
		return KeyD
	case 0x0065, 0x0045: // 'e' or 'E'
		return KeyE
	case 0x0066, 0x0046: // 'f' or 'F'
		return KeyF
	case 0x0067, 0x0047: // 'g' or 'G'
		return KeyG
	case 0x0068, 0x0048: // 'h' or 'H'
		return KeyH
	case 0x0069, 0x0049: // 'i' or 'I'
		return KeyI
	case 0x006a, 0x004a: // 'j' or 'J'
		return KeyJ
	case 0x006b, 0x004b: // 'k' or 'K'
		return KeyK
	case 0x006c, 0x004c: // 'l' or 'L'
		return KeyL
	case 0x006d, 0x004d: // 'm' or 'M'
		return KeyM
	case 0x006e, 0x004e: // 'n' or 'N'
		return KeyN
	case 0x006f, 0x004f: // 'o' or 'O'
		return KeyO
	case 0x0070, 0x0050: // 'p' or 'P'
		return KeyP
	case 0x0071, 0x0051: // 'q' or 'Q'
		return KeyQ
	case 0x0072, 0x0052: // 'r' or 'R'
		return KeyR
	case 0x0073, 0x0053: // 's' or 'S'
		return KeyS
	case 0x0074, 0x0054: // 't' or 'T'
		return KeyT
	case 0x0075, 0x0055: // 'u' or 'U'
		return KeyU
	case 0x0076, 0x0056: // 'v' or 'V'
		return KeyV
	case 0x0077, 0x0057: // 'w' or 'W'
		return KeyW
	case 0x0078, 0x0058: // 'x' or 'X'
		return KeyX
	case 0x0079, 0x0059: // 'y' or 'Y'
		return KeyY
	case 0x007a, 0x005a: // 'z' or 'Z'
		return KeyZ

	// Numbers
	case 0x0030: // '0'
		return Key0
	case 0x0031: // '1'
		return Key1
	case 0x0032: // '2'
		return Key2
	case 0x0033: // '3'
		return Key3
	case 0x0034: // '4'
		return Key4
	case 0x0035: // '5'
		return Key5
	case 0x0036: // '6'
		return Key6
	case 0x0037: // '7'
		return Key7
	case 0x0038: // '8'
		return Key8
	case 0x0039: // '9'
		return Key9

	// Function keys
	case 0xffbe: // XK_F1
		return KeyF1
	case 0xffbf: // XK_F2
		return KeyF2
	case 0xffc0: // XK_F3
		return KeyF3
	case 0xffc1: // XK_F4
		return KeyF4
	case 0xffc2: // XK_F5
		return KeyF5
	case 0xffc3: // XK_F6
		return KeyF6
	case 0xffc4: // XK_F7
		return KeyF7
	case 0xffc5: // XK_F8
		return KeyF8
	case 0xffc6: // XK_F9
		return KeyF9
	case 0xffc7: // XK_F10
		return KeyF10
	case 0xffc8: // XK_F11
		return KeyF11
	case 0xffc9: // XK_F12
		return KeyF12

	// Modifier keys
	case 0xffe1: // XK_Shift_L
		return KeyLeftShift
	case 0xffe2: // XK_Shift_R
		return KeyRightShift
	case 0xffe3: // XK_Control_L
		return KeyLeftControl
	case 0xffe4: // XK_Control_R
		return KeyRightControl
	case 0xffe9: // XK_Alt_L
		return KeyLeftAlt
	case 0xffea: // XK_Alt_R
		return KeyRightAlt
	case 0xffeb: // XK_Super_L
		return KeyLeftSuper
	case 0xffec: // XK_Super_R
		return KeyRightSuper

	// Special keys
	case 0x0020: // XK_space
		return KeySpace
	case 0xff0d: // XK_Return
		return KeyEnter
	case 0xff1b: // XK_Escape
		return KeyEscape
	case 0xff08: // XK_BackSpace
		return KeyBackspace
	case 0xffff: // XK_Delete
		return KeyDelete
	case 0xff09: // XK_Tab
		return KeyTab
	case 0xffe5: // XK_Caps_Lock
		return KeyCapsLock
	case 0xff14: // XK_Scroll_Lock
		return KeyScrollLock
	case 0xff7f: // XK_Num_Lock
		return KeyNumLock
	case 0xff61: // XK_Print
		return KeyPrintScreen
	case 0xff13: // XK_Pause
		return KeyPause

	// Arrow keys
	case 0xff52: // XK_Up
		return KeyUp
	case 0xff54: // XK_Down
		return KeyDown
	case 0xff51: // XK_Left
		return KeyLeft
	case 0xff53: // XK_Right
		return KeyRight

	// Navigation keys
	case 0xff50: // XK_Home
		return KeyHome
	case 0xff57: // XK_End
		return KeyEnd
	case 0xff55: // XK_Page_Up
		return KeyPageUp
	case 0xff56: // XK_Page_Down
		return KeyPageDown
	case 0xff63: // XK_Insert
		return KeyInsert

	// Punctuation
	case 0x0060, 0x007e: // XK_grave, XK_asciitilde
		return KeyGraveAccent
	case 0x002d, 0x005f: // XK_minus, XK_underscore
		return KeyMinus
	case 0x003d, 0x002b: // XK_equal, XK_plus
		return KeyEqual
	case 0x005b, 0x007b: // XK_bracketleft, XK_braceleft
		return KeyLeftBracket
	case 0x005d, 0x007d: // XK_bracketright, XK_braceright
		return KeyRightBracket
	case 0x005c, 0x007c: // XK_backslash, XK_bar
		return KeyBackslash
	case 0x003b, 0x003a: // XK_semicolon, XK_colon
		return KeySemicolon
	case 0x0027, 0x0022: // XK_apostrophe, XK_quotedbl
		return KeyApostrophe
	case 0x002c, 0x003c: // XK_comma, XK_less
		return KeyComma
	case 0x002e, 0x003e: // XK_period, XK_greater
		return KeyPeriod
	case 0x002f, 0x003f: // XK_slash, XK_question
		return KeySlash
	}

	return KeyUnknown
}

// buttonToButton converts an X11 button number to our Button enum
// Returns Button5+1 (invalid) for unknown buttons, which can be checked with >= ButtonLeft && <= Button5
func (w *x11Window) buttonToButton(x11Button uint32) Button {
	// X11 button mapping:
	// 1 = left button
	// 2 = middle button
	// 3 = right button
	// 4 = scroll up
	// 5 = scroll down
	switch x11Button {
	case 1:
		return ButtonLeft
	case 2:
		return ButtonMiddle
	case 3:
		return ButtonRight
	case 4:
		return Button4
	case 5:
		return Button5
	default:
		return Button5 + 1 // Invalid button (outside valid range)
	}
}

// calculateScale calculates the display scale factor based on DPI.
// It tries multiple methods in order of reliability:
// 1. GTK_SCALE environment variable (common on Wayland)
// 2. GDK_SCALE environment variable (GTK/GNOME)
// 3. QT_SCALE_FACTOR environment variable (Qt/KDE)
// 4. XSettings (used by Xwayland compositors and desktop environments)
// 5. Xft.dpi from X resources
// 6. DPI calculation from DisplayWidth/DisplayWidthMM
// 7. Default to 1.0 if all methods fail
func calculateScale(dpy uintptr, screen int32) float32 {
	// Check environment variables first (most reliable on Wayland)
	if scale := getEnvScale("GTK_SCALE"); scale > 0 {
		return roundScale(scale)
	}
	if scale := getEnvScale("GDK_SCALE"); scale > 0 {
		return roundScale(scale)
	}
	if scale := getEnvScale("QT_SCALE_FACTOR"); scale > 0 {
		return roundScale(scale)
	}

	if scale := xSettingsScale(dpy, screen); scale > 0 {
		return roundScale(scale)
	}

	// Try to get Xft.dpi from X resources (for X11)
	if xResourceManagerString != nil {
		rmString := xResourceManagerString(dpy)
		if rmString != nil {
			// Parse Xft.dpi from resource string
			// Format is like: "Xft.dpi:\t96\n..."
			rmStr := gostring(rmString)
			if dpi := parseXftDPI(rmStr); dpi > 0 {
				scale := dpi / 96.0
				// Round to common scale factors (1.0, 1.25, 1.5, 2.0, etc.)
				return roundScale(scale)
			}
		}
	}

	// Fall back to calculating DPI from physical dimensions
	if xDisplayWidth != nil && xDisplayWidthMM != nil {
		widthPx := xDisplayWidth(dpy, screen)
		widthMM := xDisplayWidthMM(dpy, screen)

		if widthMM > 0 && widthPx > 0 {
			// Calculate DPI: (pixels / millimeters) * 25.4 mm/inch
			dpi := (float32(widthPx) / float32(widthMM)) * 25.4

			// Only use this if it's reasonable (between 72 and 300 DPI)
			if dpi >= 72 && dpi <= 300 {
				scale := dpi / 96.0
				return roundScale(scale)
			}
		}
	}

	// Default to 1.0 if we can't determine scale
	return 1.0
}

func xSettingsScale(dpy uintptr, screen int32) float32 {
	if xGetSelectionOwnerCore == nil || xGetWindowPropertyCore == nil || xFreeCore == nil {
		return 0
	}
	selection := xInternAtom(dpy, cString("_XSETTINGS_S"+strconv.Itoa(int(screen))), 1)
	property := xInternAtom(dpy, cString("_XSETTINGS_SETTINGS"), 1)
	if selection == 0 || property == 0 {
		return 0
	}
	owner := xGetSelectionOwnerCore(dpy, selection)
	if owner == 0 {
		return 0
	}

	var actualType uintptr
	var actualFormat int32
	var nItems, bytesAfter uint64
	var propertyData *byte
	if result := xGetWindowPropertyCore(
		dpy, owner, property, 0, 1024*1024, 0, 0,
		&actualType, &actualFormat, &nItems, &bytesAfter, &propertyData,
	); result != 0 || propertyData == nil {
		return 0
	}
	defer xFreeCore(unsafe.Pointer(propertyData))
	if actualFormat != 8 || nItems == 0 || nItems > 4<<20 {
		return 0
	}

	data := unsafe.Slice(propertyData, int(nItems))
	return parseXSettingsScale(data)
}

func parseXSettingsScale(data []byte) float32 {
	if len(data) < 12 {
		return 0
	}
	var order binary.ByteOrder
	switch data[0] {
	case 0, 'l':
		order = binary.LittleEndian
	case 1, 'B':
		order = binary.BigEndian
	default:
		return 0
	}
	settings := int(order.Uint32(data[8:12]))
	offset := 12
	var dpiScale, windowScale float32
	for settingIndex := 0; settingIndex < settings; settingIndex++ {
		if offset+4 > len(data) {
			return 0
		}
		valueType := data[offset]
		nameLength := int(order.Uint16(data[offset+2 : offset+4]))
		offset += 4
		if nameLength < 0 || offset+nameLength > len(data) {
			return 0
		}
		name := string(data[offset : offset+nameLength])
		offset = (offset + nameLength + 3) &^ 3
		if offset+4 > len(data) {
			return 0
		}
		offset += 4 // last-change serial

		switch valueType {
		case 0:
			if offset+4 > len(data) {
				return 0
			}
			value := int32(order.Uint32(data[offset : offset+4]))
			offset += 4
			switch name {
			case "Xft/DPI":
				if value > 0 {
					dpiScale = float32(value) / (96 * 1024)
				}
			case "Gdk/WindowScalingFactor":
				if value > 0 {
					windowScale = float32(value)
				}
			}
		case 1:
			if offset+4 > len(data) {
				return 0
			}
			length := int(order.Uint32(data[offset : offset+4]))
			offset += 4
			if length < 0 || offset+length > len(data) {
				return 0
			}
			offset = (offset + length + 3) &^ 3
		case 2:
			if offset+8 > len(data) {
				return 0
			}
			offset += 8
		default:
			return 0
		}
	}
	if dpiScale > 0 {
		return dpiScale
	}
	return windowScale
}

// parseXftDPI extracts Xft.dpi value from X resource manager string
func parseXftDPI(rmString string) float32 {
	// Look for "Xft.dpi:" followed by a number
	// Simple parsing - look for the pattern
	start := -1
	for i := 0; i < len(rmString)-8; i++ {
		if rmString[i:i+8] == "Xft.dpi:" {
			start = i + 8
			break
		}
	}
	if start < 0 {
		return 0
	}

	// Skip whitespace
	for start < len(rmString) && (rmString[start] == ' ' || rmString[start] == '\t') {
		start++
	}

	// Parse the number
	var dpi float32
	var found bool
	for i := start; i < len(rmString); i++ {
		c := rmString[i]
		if c >= '0' && c <= '9' {
			dpi = dpi*10 + float32(c-'0')
			found = true
		} else if c == '.' && i+1 < len(rmString) {
			// Handle decimal point
			divisor := float32(10)
			for j := i + 1; j < len(rmString); j++ {
				c2 := rmString[j]
				if c2 >= '0' && c2 <= '9' {
					dpi += float32(c2-'0') / divisor
					divisor *= 10
					found = true
				} else {
					break
				}
			}
			break
		} else if found {
			break
		}
	}

	if found && dpi > 0 {
		return dpi
	}
	return 0
}

// roundScale rounds scale factor to common values to avoid precision issues
func roundScale(scale float32) float32 {
	// Common scale factors: 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0
	commonScales := []float32{0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0}

	// Find the closest common scale
	bestScale := float32(1.0)
	minDiff := float32(1000.0)

	for _, cs := range commonScales {
		diff := abs(scale - cs)
		if diff < minDiff {
			minDiff = diff
			bestScale = cs
		}
	}

	// Only round if we're close enough (within 0.1)
	if minDiff < 0.1 {
		return bestScale
	}

	// Otherwise return the original scale, clamped
	if scale < 0.5 {
		return 0.5
	} else if scale > 4.0 {
		return 4.0
	}
	return scale
}

// getEnvScale reads a scale factor from an environment variable
func getEnvScale(envVar string) float32 {
	val := os.Getenv(envVar)
	if val == "" {
		return 0
	}

	scale, err := strconv.ParseFloat(val, 32)
	if err != nil {
		return 0
	}

	if scale > 0 {
		return float32(scale)
	}
	return 0
}

func abs(x float32) float32 {
	if x < 0 {
		return -x
	}
	return x
}

func gostring(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	var bytes []byte
	for p := ptr; *p != 0; p = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + 1)) {
		bytes = append(bytes, *p)
	}
	return string(bytes)
}

type xSetWindowAttributes struct {
	BackgroundPixmap uintptr
	BackgroundPixel  uint64
	BorderPixmap     uint64
	BorderPixel      uint64
	BitGravity       int32
	WinGravity       int32
	BackingStore     int32
	BackingPlanes    uint64
	BackingPixel     uint64
	SaveUnder        int32
	EventMask        int64
	DoNotPropagate   int64
	OverrideRedirect int32
	Colormap         uintptr
	Cursor           uintptr
}

func ensureLibs() error {
	var err error
	if x11lib == 0 {
		x11lib, err = purego.Dlopen("libX11.so.6", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
		if err != nil {
			return err
		}
		registerX11()
	}
	if gllib == 0 {
		gllib, err = purego.Dlopen("libGL.so.1", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
		if err != nil {
			return err
		}
		registerGLX()
	}
	return nil
}

func registerX11() {
	purego.RegisterLibFunc(&xOpenDisplay, x11lib, "XOpenDisplay")
	registerDesktopFunctions()
	purego.RegisterLibFunc(&xDefaultScreen, x11lib, "XDefaultScreen")
	purego.RegisterLibFunc(&xRootWindow, x11lib, "XRootWindow")
	purego.RegisterLibFunc(&xCreateColormap, x11lib, "XCreateColormap")
	purego.RegisterLibFunc(&xCreateWindow, x11lib, "XCreateWindow")
	purego.RegisterLibFunc(&xMapWindow, x11lib, "XMapWindow")
	purego.RegisterLibFunc(&xStoreName, x11lib, "XStoreName")
	purego.RegisterLibFunc(&xInternAtom, x11lib, "XInternAtom")
	purego.RegisterLibFunc(&xSetWMProtocols, x11lib, "XSetWMProtocols")
	purego.RegisterLibFunc(&xSelectInput, x11lib, "XSelectInput")
	purego.RegisterLibFunc(&xPending, x11lib, "XPending")
	purego.RegisterLibFunc(&xNextEvent, x11lib, "XNextEvent")
	purego.RegisterLibFunc(&xGetGeometry, x11lib, "XGetGeometry")
	purego.RegisterLibFunc(&xDestroyWindow, x11lib, "XDestroyWindow")
	purego.RegisterLibFunc(&xCloseDisplay, x11lib, "XCloseDisplay")
	purego.RegisterLibFunc(&xQueryPointer, x11lib, "XQueryPointer")
	purego.RegisterLibFunc(&xDisplayWidth, x11lib, "XDisplayWidth")
	purego.RegisterLibFunc(&xDisplayWidthMM, x11lib, "XDisplayWidthMM")
	purego.RegisterLibFunc(&xDisplayHeight, x11lib, "XDisplayHeight")
	purego.RegisterLibFunc(&xDisplayHeightMM, x11lib, "XDisplayHeightMM")
	purego.RegisterLibFunc(&xGetSelectionOwnerCore, x11lib, "XGetSelectionOwner")
	purego.RegisterLibFunc(&xGetWindowPropertyCore, x11lib, "XGetWindowProperty")
	purego.RegisterLibFunc(&xFreeCore, x11lib, "XFree")
	// Try to register XResourceManagerString, but don't fail if it's not available
	if _, err := purego.Dlsym(x11lib, "XResourceManagerString"); err == nil {
		purego.RegisterLibFunc(&xResourceManagerString, x11lib, "XResourceManagerString")
	} else {
		// Function not available, will fall back to DPI calculation
		xResourceManagerString = nil
	}
	// Try to register XLookupKeysym, but don't fail if it's not available
	if _, err := purego.Dlsym(x11lib, "XLookupKeysym"); err == nil {
		purego.RegisterLibFunc(&xLookupKeysym, x11lib, "XLookupKeysym")
	} else {
		// Function not available, key mapping will be limited
		xLookupKeysym = nil
	}
}

func registerGLX() {
	purego.RegisterLibFunc(&glxChooseVisual, gllib, "glXChooseVisual")
	purego.RegisterLibFunc(&glxCreateContext, gllib, "glXCreateContext")
	purego.RegisterLibFunc(&glxMakeCurrent, gllib, "glXMakeCurrent")
	purego.RegisterLibFunc(&glxSwapBuffers, gllib, "glXSwapBuffers")
	purego.RegisterLibFunc(&glxDestroyContext, gllib, "glXDestroyContext")

	// Try to register GLX_ARB_create_context functions
	if _, err := purego.Dlsym(gllib, "glXChooseFBConfig"); err == nil {
		purego.RegisterLibFunc(&glxChooseFBConfig, gllib, "glXChooseFBConfig")
	}
	if _, err := purego.Dlsym(gllib, "glXGetVisualFromFBConfig"); err == nil {
		purego.RegisterLibFunc(&glxGetVisualFromFBConfig, gllib, "glXGetVisualFromFBConfig")
	}
	if _, err := purego.Dlsym(gllib, "glXCreateContextAttribsARB"); err == nil {
		purego.RegisterLibFunc(&glxCreateContextAttribsARB, gllib, "glXCreateContextAttribsARB")
	}
	// glXGetProcAddressARB is needed for loading OpenGL functions
	if _, err := purego.Dlsym(gllib, "glXGetProcAddressARB"); err == nil {
		purego.RegisterLibFunc(&glXGetProcAddressARB, gllib, "glXGetProcAddressARB")
	}
}

func cString(s string) *byte {
	b := append([]byte(s), 0)
	return &b[0]
}

// getDisplayScale returns the display scale factor by querying X11.
// This function can be called before creating a window.
func getDisplayScale() float32 {
	if err := ensureLibs(); err != nil {
		return 1.0
	}

	dpy := xOpenDisplay(nil)
	if dpy == 0 {
		return 1.0
	}
	defer xCloseDisplay(dpy)

	screen := xDefaultScreen(dpy)
	return calculateScale(dpy, screen)
}
