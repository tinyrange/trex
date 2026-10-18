package xwindow

import "fmt"

// Key represents a keyboard key.
type Key int

const (
	KeyUnknown Key = iota

	// Letters
	KeyA
	KeyB
	KeyC
	KeyD
	KeyE
	KeyF
	KeyG
	KeyH
	KeyI
	KeyJ
	KeyK
	KeyL
	KeyM
	KeyN
	KeyO
	KeyP
	KeyQ
	KeyR
	KeyS
	KeyT
	KeyU
	KeyV
	KeyW
	KeyX
	KeyY
	KeyZ

	// Numbers
	Key0
	Key1
	Key2
	Key3
	Key4
	Key5
	Key6
	Key7
	Key8
	Key9

	// Function keys
	KeyF1
	KeyF2
	KeyF3
	KeyF4
	KeyF5
	KeyF6
	KeyF7
	KeyF8
	KeyF9
	KeyF10
	KeyF11
	KeyF12

	// Modifier keys
	KeyLeftShift
	KeyRightShift
	KeyLeftControl
	KeyRightControl
	KeyLeftAlt
	KeyRightAlt
	KeyLeftSuper  // Windows key on Windows, Command key on macOS
	KeyRightSuper // Windows key on Windows, Command key on macOS

	// Special keys
	KeySpace
	KeyEnter
	KeyEscape
	KeyBackspace
	KeyDelete
	KeyTab
	KeyCapsLock
	KeyScrollLock
	KeyNumLock
	KeyPrintScreen
	KeyPause

	// Arrow keys
	KeyUp
	KeyDown
	KeyLeft
	KeyRight

	// Navigation keys
	KeyHome
	KeyEnd
	KeyPageUp
	KeyPageDown
	KeyInsert

	// Punctuation and symbols
	KeyGraveAccent  // `
	KeyMinus        // -
	KeyEqual        // =
	KeyLeftBracket  // [
	KeyRightBracket // ]
	KeyBackslash    // \
	KeySemicolon    // ;
	KeyApostrophe   // '
	KeyComma        // ,
	KeyPeriod       // .
	KeySlash        // /

	// Numpad keys
	KeyNumpad0
	KeyNumpad1
	KeyNumpad2
	KeyNumpad3
	KeyNumpad4
	KeyNumpad5
	KeyNumpad6
	KeyNumpad7
	KeyNumpad8
	KeyNumpad9
	KeyNumpadDecimal  // .
	KeyNumpadDivide   // /
	KeyNumpadMultiply // *
	KeyNumpadSubtract // -
	KeyNumpadAdd      // +
	KeyNumpadEnter
	KeyNumpadEqual // =
)

// Button represents a mouse button.
type Button int

const (
	ButtonLeft Button = iota
	ButtonRight
	ButtonMiddle
	Button4 // Additional mouse button (often back button)
	Button5 // Additional mouse button (often forward button)
)

// KeyState represents the state of a keyboard key.
type KeyState int

const (
	// KeyStatePressed indicates the key was pressed this frame
	KeyStatePressed KeyState = iota
	// KeyStateDown indicates the key is currently down
	KeyStateDown
	// KeyStateReleased indicates the key was released this frame
	KeyStateReleased
	// KeyStateUp indicates the key is currently up
	KeyStateUp
	// KeyStateRepeated indicates the key is being held down (repeated)
	KeyStateRepeated
)

// ButtonState represents the state of a mouse button.
type ButtonState int

const (
	// ButtonStatePressed indicates the button was pressed this frame
	ButtonStatePressed ButtonState = iota
	// ButtonStateDown indicates the button is currently down
	ButtonStateDown
	// ButtonStateReleased indicates the button was released this frame
	ButtonStateReleased
	// ButtonStateUp indicates the button is currently up
	ButtonStateUp
)

// IsDown returns true if the key state indicates the key is currently down.
func (ks KeyState) IsDown() bool {
	return ks == KeyStatePressed || ks == KeyStateDown || ks == KeyStateRepeated
}

// IsDown returns true if the button state indicates the button is currently down.
func (bs ButtonState) IsDown() bool {
	return bs == ButtonStatePressed || bs == ButtonStateDown
}

// KeyMods represents currently active keyboard modifiers.
type KeyMods uint8

const (
	ModShift KeyMods = 1 << iota
	ModCtrl
	ModAlt
	ModSuper
)

// InputEventType describes the kind of input event.
type InputEventType uint8

const (
	InputEventKeyDown InputEventType = iota
	InputEventKeyUp
	InputEventFlagsChanged
	InputEventText
	InputEventMouseDown
	InputEventMouseUp
	InputEventMouseMove
	InputEventScroll
	InputEventPinch
)

func (t InputEventType) String() string {
	switch t {
	case InputEventKeyDown:
		return "KeyDown"
	case InputEventKeyUp:
		return "KeyUp"
	case InputEventFlagsChanged:
		return "FlagsChanged"
	case InputEventText:
		return "Text"
	case InputEventMouseDown:
		return "MouseDown"
	case InputEventMouseUp:
		return "MouseUp"
	case InputEventMouseMove:
		return "MouseMove"
	case InputEventScroll:
		return "Scroll"
	case InputEventPinch:
		return "Pinch"
	default:
		return fmt.Sprintf("InputEventType(%d)", uint8(t))
	}
}

// InputEvent is a raw input event emitted by a platform window backend.
//
// Contract:
// - Events are queued during Poll() and returned by DrainInputEvents().
// - DrainInputEvents() clears the internal queue.
type InputEvent struct {
	Type   InputEventType
	Key    Key
	Text   string
	Mods   KeyMods
	Repeat bool

	// Button is meaningful for MouseDown/MouseUp.
	// For MouseMove, Button may identify the button associated with a platform
	// drag event; otherwise use Window.GetButtonState to inspect active buttons.
	Button Button
	// ButtonValid reports whether Button was populated for this event. It is
	// true for MouseDown/MouseUp and for platform drag MouseMove events.
	ButtonValid bool

	// MouseX/MouseY are meaningful for MouseDown, MouseUp, and MouseMove events.
	// They are in the same backing-pixel coordinate space as Window.Cursor.
	MouseX float32
	MouseY float32

	// MouseDeltaX/MouseDeltaY are meaningful for MouseMove events when the
	// platform reports relative movement. They are especially useful while the
	// cursor is captured and absolute cursor position no longer changes normally.
	MouseDeltaX float32
	MouseDeltaY float32

	// ScrollX/ScrollY are meaningful for Scroll events. Values are in "wheel ticks"
	// where 1.0 corresponds to a standard mouse wheel notch (platform-dependent).
	// Existing mouse-wheel callers should continue to use these fields.
	ScrollX float32
	ScrollY float32

	// RawScrollX/RawScrollY are meaningful for Scroll events and preserve the
	// platform's high-resolution scroll units where available. On macOS precise
	// scrolling devices these are NSEvent scrollingDelta values in logical
	// points. On coarse wheel platforms they match ScrollX/ScrollY.
	RawScrollX float32
	RawScrollY float32

	// PreciseScroll reports whether Scroll came from a high-resolution scrolling
	// device such as a touchpad. Platforms that cannot distinguish precision
	// scrolling leave this false.
	PreciseScroll bool

	// PinchScale is meaningful for Pinch events. It is a multiplicative scale
	// delta for the gesture event; values greater than 1 zoom in and values less
	// than 1 zoom out.
	PinchScale float32

	// PinchDelta is meaningful for Pinch events and carries the raw platform
	// magnification delta when available. On macOS this is NSEvent magnification.
	PinchDelta float32
}

const InputEventFocusLost InputEventType = 255
